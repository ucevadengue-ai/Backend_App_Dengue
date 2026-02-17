using Backend_App_Dengue.Data.Entities;
using Backend_App_Dengue.Data;
using Backend_App_Dengue.Data.Repositories;
using Backend_App_Dengue.Model;
using Backend_App_Dengue.Model.Dto;
using Backend_App_Dengue.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore;

namespace Backend_App_Dengue.Controllers
{
    /// <summary>
    /// Controlador de autenticación y registro de usuarios
    /// </summary>
    [Route("Auth")]
    [ApiController]
    [Produces("application/json")]
    public class AuthControllerEF : ControllerBase
    {
        private readonly IRepository<User> _userRepository;
        private readonly AppDbContext _context;
        private readonly JwtService _jwtService;
        private readonly IRepository<UserApprovalRequest> _approvalRequestRepository;

        public AuthControllerEF(IRepository<User> userRepository, JwtService jwtService, AppDbContext context, IRepository<UserApprovalRequest> approvalRequestRepository)
        {
            _userRepository = userRepository;
            _context = context;
            _jwtService = jwtService;
            _approvalRequestRepository = approvalRequestRepository;
        }

        /// <summary>
        /// Autenticación de usuario con email y contraseña usando BCrypt
        /// </summary>
        /// <param name="credentials">Credenciales de login (email y contraseña)</param>
        /// <returns>Datos del usuario con access token y refresh token</returns>
        /// <response code="200">Login exitoso, retorna datos del usuario y tokens</response>
        /// <response code="400">Email y contraseña son requeridos</response>
        /// <response code="401">Credenciales inválidas o usuario inactivo</response>
        /// <response code="500">Error interno del servidor</response>
        [HttpPost]
        [Route("login")]
        [ProducesResponseType(typeof(AuthResponseDto), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        [Consumes("application/json")]
        public async Task<IActionResult> Login([FromBody] LoginModelDto credentials)
        {
            if (credentials == null || string.IsNullOrEmpty(credentials.email) || string.IsNullOrEmpty(credentials.password))
            {
                return BadRequest(new { message = "Email y contraseña son requeridos" });
            }

            try
            {
                // Buscar usuario por email
                var user = await _context.Users
                    .Include(u => u.Role)
                        .ThenInclude(r => r.RolePermissions)
                            .ThenInclude(rp => rp.Permission)
                    .Include(u => u.City).ThenInclude(c => c.Department)
                    .Include(u => u.BloodType)
                    .Include(u => u.Genre)
                    .FirstOrDefaultAsync(u => u.Email == credentials.email);

                if (user == null)
                {
                    return Unauthorized(new { message = "No se ha encontrado al usuario" });
                }

                // Verificar contraseña con BCrypt
                bool isValidPassword = BCrypt.Net.BCrypt.Verify(credentials.password, user.Password);

                if (!isValidPassword)
                {
                    return Unauthorized(new { message = "Credenciales inválidas" });
                }

                // Verificar si el usuario está activo
                if (!user.IsActive)
                {
                    return Unauthorized(new { message = "Usuario inactivo" });
                }

                // Generar access token JWT
                string accessToken = _jwtService.GenerateToken(user);

                // Generar refresh token
                string refreshToken = _jwtService.GenerateRefreshToken();

                // Revocar refresh tokens anteriores del usuario (opcional - para un solo dispositivo)
                var oldTokens = await _context.RefreshTokens
                    .Where(rt => rt.UserId == user.Id && !rt.IsRevoked)
                    .ToListAsync();

                foreach (var oldToken in oldTokens)
                {
                    oldToken.IsRevoked = true;
                    oldToken.RevokedAt = DateTime.Now;
                }

                // Guardar nuevo refresh token en la base de datos
                var newRefreshToken = new RefreshToken
                {
                    UserId = user.Id,
                    Token = refreshToken,
                    ExpiresAt = DateTime.UtcNow.AddDays(30), // 30 días de validez
                    DeviceInfo = Request.Headers.UserAgent.ToString()
                };

                await _context.RefreshTokens.AddAsync(newRefreshToken);
                await _context.SaveChangesAsync();

                // Convertir a DTO
                var userDto = user.ToResponseDto();

                // Obtener permisos del usuario
                var permissions = user.Role.RolePermissions
                    .Where(rp => rp.IsActive && rp.Permission.IsActive)
                    .Select(rp => rp.Permission.Code)
                    .Distinct()
                    .OrderBy(code => code)
                    .ToList();

                // Retornar respuesta con tokens y permisos
                var response = new AuthResponseDto
                {
                    User = new UserResponseDto
                    {
                        Id = userDto.Id,
                        Name = userDto.Name,
                        Email = userDto.Email,
                        Password = null, // No retornar password por seguridad
                        Address = userDto.Address,
                        RoleId = userDto.RoleId,
                        RoleName = userDto.RoleName,
                        CityId = userDto.CityId,
                        CityName = userDto.CityName,
                        BloodTypeId = userDto.BloodTypeId,
                        BloodTypeName = userDto.BloodTypeName,
                        GenreId = userDto.GenreId,
                        GenreName = userDto.GenreName,
                        DepartmentId = userDto.DepartmentId,
                        UserStateName = userDto.UserStateName
                    },
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = _jwtService.GetAccessTokenExpirationMinutes() * 60, // Convertir a segundos
                    Permissions = permissions // NUEVO: Incluir permisos en la respuesta
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Error al iniciar sesión", error = ex.Message });
            }
        }

        /// <summary>
        /// Registra un nuevo usuario con encriptación BCrypt de contraseña
        /// </summary>
        /// <param name="usuario">Datos del nuevo usuario</param>
        /// <returns>Usuario creado exitosamente</returns>
        /// <response code="200">Usuario registrado exitosamente</response>
        /// <response code="400">Datos incompletos o inválidos</response>
        /// <response code="409">El correo ya está registrado</response>
        /// <response code="500">Error interno del servidor</response>
        /// <remarks>
        /// Envía un email de bienvenida automáticamente.
        /// La contraseña se encripta con BCrypt antes de almacenarse.
        /// </remarks>
        [HttpPost]
        [Route("register")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(409)]
        [ProducesResponseType(500)]
        [Consumes("application/json")]
        public async Task<IActionResult> Register([FromBody] RegisterUserModel usuario)
        {
            if (usuario == null)
            {
                return BadRequest(new { message = "Los datos del usuario son requeridos" });
            }

            try
            {
                // Validar campos requeridos
                if (string.IsNullOrWhiteSpace(usuario.NOMBRE_USUARIO) ||
                    string.IsNullOrWhiteSpace(usuario.CORREO_USUARIO) ||
                    string.IsNullOrWhiteSpace(usuario.CONTRASENIA_USUARIO))
                {
                    return BadRequest(new { message = "Nombre, correo y contraseña son requeridos" });
                }

                // Verificar si el email ya existe
                var existingUser = await _userRepository.FirstOrDefaultAsync(u => u.Email == usuario.CORREO_USUARIO);

                if (existingUser != null)
                {
                    return Conflict(new { message = "El correo ya se encuentra registrado" });
                }

                // Hash de contraseña con BCrypt (genera salt automáticamente)
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(usuario.CONTRASENIA_USUARIO);

                // Parsear fecha de nacimiento si se proporciona
                DateTime? birthDate = null;
                if (!string.IsNullOrWhiteSpace(usuario.FECHA_NACIMIENTO_USUARIO))
                {
                    if (DateTime.TryParse(usuario.FECHA_NACIMIENTO_USUARIO, out DateTime parsedDate))
                    {
                        birthDate = parsedDate;
                    }
                }

                // Crear nuevo usuario
                var newUser = new User
                {
                    Name = usuario.NOMBRE_USUARIO,
                    Email = usuario.CORREO_USUARIO,
                    Password = hashedPassword,
                    Address = usuario.DIRECCION_USUARIO ?? string.Empty,
                    BirthDate = birthDate,
                    RoleId = usuario.FK_ID_ROL,
                    CityId = usuario.FK_ID_MUNICIPIO,
                    BloodTypeId = usuario.FK_ID_TIPOSANGRE,
                    GenreId = usuario.FK_ID_GENERO,
                    IsActive = true
                };

                var createdUser = await _userRepository.AddAsync(newUser);

                // Enviar email de bienvenida con plantilla moderna
                try
                {
                    ServiceGmail emailService = new ServiceGmail();
                    string htmlBody = EmailTemplates.WelcomeTemplate(usuario.NOMBRE_USUARIO, usuario.CORREO_USUARIO);
                    await Task.Run(() => emailService.SendEmailGmail(
                        usuario.CORREO_USUARIO,
                        "¡Bienvenido a Dengue Track!",
                        htmlBody
                    ));
                }
                catch (Exception emailEx)
                {
                    // Registrar error de email pero no fallar el registro
                    Console.WriteLine($"Error al enviar email de bienvenida: {emailEx.Message}");
                }

                // Retornar usuario creado (la contraseña no se expondrá en la respuesta debido a las propiedades de navegación)
                return Ok(new { message = "Usuario creado con éxito", usuario = createdUser });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al registrar usuario: {ex.Message}");
                return StatusCode(500, new { message = "Error al registrar usuario. Por favor, intenta nuevamente." });
            }
        }

        /// <summary>
        /// Recuperación de contraseña - genera nueva contraseña aleatoria y la envía por email
        /// </summary>
        /// <param name="request">Email del usuario</param>
        /// <returns>Confirmación de envío de email</returns>
        /// <response code="200">Email enviado exitosamente (no revela si el email existe)</response>
        /// <response code="400">El email es requerido</response>
        /// <response code="500">Error al recuperar contraseña</response>
        /// <remarks>
        /// Por seguridad, siempre retorna 200 sin revelar si el email existe en el sistema.
        /// La nueva contraseña es segura con mayúsculas, minúsculas, números y caracteres especiales.
        /// </remarks>
        [HttpPost]
        [Route("recoverPassword")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(500)]
        [Consumes("application/json")]
        public async Task<IActionResult> RecoverPassword([FromBody] RecoverPasswordDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.Email))
            {
                return BadRequest(new { message = "El email es requerido" });
            }

            try
            {
                // Buscar usuario por email
                var user = await _userRepository.FirstOrDefaultAsync(u => u.Email == request.Email);

                if (user == null)
                {
                    // No revelar si el email existe o no (buena práctica de seguridad)
                    return Ok(new { message = "Si el correo existe, se enviará la nueva contraseña" });
                }

                // Generar nueva contraseña segura
                string newPassword = GenerarClaveSegura();

                // Hash de nueva contraseña con BCrypt
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(newPassword);

                // Actualizar contraseña del usuario
                user.Password = hashedPassword;
                await _userRepository.UpdateAsync(user);

                // Enviar email con nueva contraseña usando plantilla HTML moderna
                ServiceGmail emailService = new ServiceGmail();
                string htmlBody = EmailTemplates.RecoverPasswordTemplate(newPassword, request.Email);
                await Task.Run(() => emailService.SendEmailGmail(
                    request.Email,
                    "Recuperación de Contraseña - Dengue Track",
                    htmlBody
                ));

                return Ok(new { message = "Contraseña enviada al correo con éxito" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Error al recuperar contraseña", error = ex.Message });
            }
        }

        /// <summary>
        /// Valida identidad de personal médico contra el sistema externo RETHUS
        /// </summary>
        /// <param name="request">Datos de identificación del profesional de salud</param>
        /// <returns>Resultado de la validación RETHUS</returns>
        /// <response code="200">Validación completada (puede ser exitosa o fallida)</response>
        /// <response code="400">Todos los campos son requeridos</response>
        /// <response code="503">Servicio RETHUS no disponible</response>
        /// <response code="500">Error al validar con RETHUS</response>
        /// <remarks>
        /// Requiere: tipo de identificación, número de identificación, primer nombre y primer apellido.
        /// Se conecta al servicio externo RETHUS para validar profesionales de la salud.
        /// </remarks>
        [HttpPost]
        [Route("Rethus")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(503)]
        [ProducesResponseType(500)]
        [Consumes("application/json")]
        public async Task<IActionResult> Rethus([FromBody] RethusRequestDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.PrimerNombre) ||
                string.IsNullOrEmpty(request.PrimerApellido) ||
                string.IsNullOrEmpty(request.TipoIdentificacion) ||
                string.IsNullOrEmpty(request.Cedula))
            {
                return BadRequest(new { message = "Todos los campos son requeridos" });
            }

            try
            {
                using var client = new HttpClient();
                client.BaseAddress = new Uri("https://v31ppm97-8000.use.devtunnels.ms");
                client.Timeout = TimeSpan.FromSeconds(30);

                var formData = new Dictionary<string, string>
                {
                    { "tipo_identificacion", request.TipoIdentificacion },
                    { "numero_identificacion", request.Cedula },
                    { "primer_nombre", request.PrimerNombre },
                    { "primer_apellido", request.PrimerApellido }
                };

                var content = new FormUrlEncodedContent(formData);
                var response = await client.PostAsync("/validar", content);

                if (response.IsSuccessStatusCode)
                {
                    // Simplemente devolver lo que RETHUS responde directamente
                    var result = await response.Content.ReadAsStringAsync();

                    // Parsear y devolver el mismo formato
                    var rethusData = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(result);
                    var status = rethusData.GetProperty("status").GetString();
                    var message = rethusData.TryGetProperty("message", out var msgProp) ? msgProp.GetString() : "";

                    return Ok(new { status = status, message = message });
                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, new { status = "error", message = "Error en la consulta RETHUS" });
                }
            }
            catch (HttpRequestException ex)
            {
                return StatusCode(503, new { message = "Servicio RETHUS no disponible", error = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Error al validar con RETHUS", error = ex.Message });
            }
        }

        /// <summary>
        /// Renueva el access token usando un refresh token válido
        /// </summary>
        /// <param name="request">Refresh token del usuario</param>
        /// <returns>Nuevo access token</returns>
        /// <response code="200">Token renovado exitosamente</response>
        /// <response code="400">Refresh token es requerido</response>
        /// <response code="401">Refresh token inválido, expirado o revocado</response>
        /// <response code="500">Error al renovar token</response>
        [HttpPost]
        [Route("refresh")]
        [ProducesResponseType(typeof(RefreshTokenResponseDto), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        [Consumes("application/json")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.RefreshToken))
            {
                return BadRequest(new { message = "El refresh token es requerido" });
            }

            try
            {
                // Buscar el refresh token en la base de datos
                var refreshToken = await _context.RefreshTokens
                    .Include(rt => rt.User)
                        .ThenInclude(u => u.Role)
                    .Include(rt => rt.User.City)
                        .ThenInclude(c => c.Department)
                    .Include(rt => rt.User.BloodType)
                    .Include(rt => rt.User.Genre)
                    .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

                // Validar que el refresh token exista
                if (refreshToken == null)
                {
                    return Unauthorized(new { message = "Refresh token inválido" });
                }

                // Validar que no esté revocado
                if (refreshToken.IsRevoked)
                {
                    return Unauthorized(new { message = "Refresh token ha sido revocado" });
                }

                // Validar que no haya expirado
                if (refreshToken.ExpiresAt < DateTime.UtcNow)
                {
                    return Unauthorized(new { message = "Refresh token ha expirado" });
                }

                // Validar que el usuario esté activo
                if (!refreshToken.User.IsActive)
                {
                    return Unauthorized(new { message = "Usuario inactivo" });
                }

                // Generar nuevo access token
                string newAccessToken = _jwtService.GenerateToken(refreshToken.User);

                // Retornar nuevo access token
                var response = new RefreshTokenResponseDto
                {
                    AccessToken = newAccessToken,
                    ExpiresIn = _jwtService.GetAccessTokenExpirationMinutes() * 60 // Convertir a segundos
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Error al renovar token", error = ex.Message });
            }
        }

        /// <summary>
        /// Registra un usuario con validación RETHUS. Si RETHUS falla, crea el usuario con rol básico y solicitud de aprobación pendiente
        /// </summary>
        /// <param name="usuario">Datos del usuario</param>
        /// <param name="rethusData">Datos para validación RETHUS (opcional)</param>
        /// <returns>Usuario creado</returns>
        /// <response code="200">Usuario registrado exitosamente</response>
        /// <response code="400">Datos inválidos</response>
        /// <response code="409">Email ya registrado</response>
        /// <response code="500">Error al registrar usuario</response>
        [HttpPost]
        [Route("register-with-rethus")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(409)]
        [ProducesResponseType(500)]
        [Consumes("application/json")]
        public async Task<IActionResult> RegisterWithRethus([FromBody] RegisterUserModel usuario, [FromQuery] string? tipoIdentificacion = null, [FromQuery] string? numeroIdentificacion = null, [FromQuery] string? primerNombre = null, [FromQuery] string? primerApellido = null, [FromQuery] int? rolSolicitado = null)
        {
            if (usuario == null)
            {
                return BadRequest(new { message = "Los datos del usuario son requeridos" });
            }

            try
            {
                // Validar campos requeridos
                if (string.IsNullOrWhiteSpace(usuario.NOMBRE_USUARIO) ||
                    string.IsNullOrWhiteSpace(usuario.CORREO_USUARIO) ||
                    string.IsNullOrWhiteSpace(usuario.CONTRASENIA_USUARIO))
                {
                    return BadRequest(new { message = "Nombre, correo y contraseña son requeridos" });
                }

                // Verificar si el email ya existe
                var existingUser = await _userRepository.FirstOrDefaultAsync(u => u.Email == usuario.CORREO_USUARIO);

                if (existingUser != null)
                {
                    return Conflict(new { message = "El correo ya se encuentra registrado" });
                }

                // Hash de contraseña con BCrypt
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(usuario.CONTRASENIA_USUARIO);

                // Parsear fecha de nacimiento si se proporciona
                DateTime? birthDate = null;
                if (!string.IsNullOrWhiteSpace(usuario.FECHA_NACIMIENTO_USUARIO))
                {
                    if (DateTime.TryParse(usuario.FECHA_NACIMIENTO_USUARIO, out DateTime parsedDate))
                    {
                        birthDate = parsedDate;
                    }
                }

                bool rethusSuccess = false;
                string? rethusError = null;
                int assignedRoleId = usuario.FK_ID_ROL; // Rol por defecto del formulario

                // Intentar validar con RETHUS si se proporcionaron datos
                if (!string.IsNullOrEmpty(tipoIdentificacion) && !string.IsNullOrEmpty(numeroIdentificacion) &&
                    !string.IsNullOrEmpty(primerNombre) && !string.IsNullOrEmpty(primerApellido))
                {
                    try
                    {
                        using var client = new HttpClient();
                        client.BaseAddress = new Uri("https://v31ppm97-8000.use.devtunnels.ms");
                        client.Timeout = TimeSpan.FromSeconds(10); // Timeout más corto

                        var formData = new Dictionary<string, string>
                        {
                            { "tipo_identificacion", tipoIdentificacion },
                            { "numero_identificacion", numeroIdentificacion },
                            { "primer_nombre", primerNombre },
                            { "primer_apellido", primerApellido }
                        };

                        var content = new FormUrlEncodedContent(formData);
                        var response = await client.PostAsync("/validar", content);

                        if (response.IsSuccessStatusCode)
                        {
                            var result = await response.Content.ReadAsStringAsync();
                            var rethusData = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(result);
                            var status = rethusData.GetProperty("status").GetString();

                            if (status == "success")
                            {
                                rethusSuccess = true;
                                // Si RETHUS valida correctamente, usar el rol solicitado
                                if (rolSolicitado.HasValue)
                                {
                                    assignedRoleId = rolSolicitado.Value;
                                }
                            }
                            else
                            {
                                rethusError = "Validación RETHUS falló: credenciales no encontradas";
                            }
                        }
                        else
                        {
                            rethusError = $"Servicio RETHUS no disponible (HTTP {response.StatusCode})";
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        rethusError = $"Servicio RETHUS no disponible: {ex.Message}";
                    }
                    catch (TaskCanceledException)
                    {
                        rethusError = "Timeout al conectar con servicio RETHUS";
                    }
                    catch (Exception ex)
                    {
                        rethusError = $"Error al validar con RETHUS: {ex.Message}";
                    }
                }

                // Si RETHUS falló o no se intentó validar, usar rol básico (ID 1 típicamente es "Usuario")
                if (!rethusSuccess && rolSolicitado.HasValue)
                {
                    assignedRoleId = 1; // Rol básico por defecto
                }

                // Crear nuevo usuario
                var newUser = new User
                {
                    Name = usuario.NOMBRE_USUARIO,
                    Email = usuario.CORREO_USUARIO,
                    Password = hashedPassword,
                    Address = usuario.DIRECCION_USUARIO ?? string.Empty,
                    BirthDate = birthDate,
                    RoleId = assignedRoleId,
                    CityId = usuario.FK_ID_MUNICIPIO,
                    BloodTypeId = usuario.FK_ID_TIPOSANGRE,
                    GenreId = usuario.FK_ID_GENERO,
                    IsActive = true
                };

                var createdUser = await _userRepository.AddAsync(newUser);

                // Si RETHUS falló y había un rol solicitado diferente, crear solicitud de aprobación
                if (!rethusSuccess && rolSolicitado.HasValue && rolSolicitado.Value != assignedRoleId)
                {
                    var approvalRequest = new UserApprovalRequest
                    {
                        UserId = createdUser.Id,
                        RequestedRoleId = rolSolicitado.Value,
                        Status = "PENDIENTE",
                        RequestDate = DateTime.Now,
                        RethusData = System.Text.Json.JsonSerializer.Serialize(new
                        {
                            tipo_identificacion = tipoIdentificacion,
                            numero_identificacion = numeroIdentificacion,
                            primer_nombre = primerNombre,
                            primer_apellido = primerApellido
                        }),
                        RethusError = rethusError
                    };

                    await _approvalRequestRepository.AddAsync(approvalRequest);
                }

                // Enviar email de bienvenida
                try
                {
                    ServiceGmail emailService = new ServiceGmail();
                    string htmlBody = EmailTemplates.WelcomeTemplate(usuario.NOMBRE_USUARIO, usuario.CORREO_USUARIO);
                    await Task.Run(() => emailService.SendEmailGmail(
                        usuario.CORREO_USUARIO,
                        "¡Bienvenido a Dengue Track!",
                        htmlBody
                    ));
                }
                catch (Exception emailEx)
                {
                    Console.WriteLine($"Error al enviar email de bienvenida: {emailEx.Message}");
                }

                var responseMessage = rethusSuccess
                    ? "Usuario creado con éxito y verificado con RETHUS"
                    : (!string.IsNullOrEmpty(rethusError))
                        ? "Usuario creado con éxito. Solicitud de aprobación pendiente (RETHUS no disponible)"
                        : "Usuario creado con éxito";

                return Ok(new
                {
                    message = responseMessage,
                    usuario = new
                    {
                        id = createdUser.Id,
                        nombre = createdUser.Name,
                        email = createdUser.Email,
                        rolId = createdUser.RoleId
                    },
                    rethusValidado = rethusSuccess,
                    solicitudPendiente = !rethusSuccess && rolSolicitado.HasValue && rolSolicitado.Value != assignedRoleId
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al registrar usuario: {ex.Message}");
                return StatusCode(500, new { message = "Error al registrar usuario. Por favor, intenta nuevamente." });
            }
        }

        /// <summary>
        /// Cambia la contraseña del usuario desde su perfil
        /// </summary>
        /// <param name="userId">ID del usuario</param>
        /// <param name="request">Contraseña actual y nueva contraseña</param>
        /// <returns>Confirmación de cambio de contraseña</returns>
        /// <response code="200">Contraseña cambiada exitosamente</response>
        /// <response code="400">Datos inválidos o contraseñas no coinciden</response>
        /// <response code="401">Contraseña actual incorrecta</response>
        /// <response code="404">Usuario no encontrado</response>
        /// <response code="500">Error al cambiar contraseña</response>
        [HttpPost]
        [Route("changePassword/{userId}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        [Consumes("application/json")]
        public async Task<IActionResult> ChangePassword(int userId, [FromBody] ChangePasswordDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.CurrentPassword) ||
                string.IsNullOrEmpty(request.NewPassword) || string.IsNullOrEmpty(request.ConfirmPassword))
            {
                return BadRequest(new { message = "Todos los campos son requeridos" });
            }

            if (request.NewPassword != request.ConfirmPassword)
            {
                return BadRequest(new { message = "La nueva contraseña y su confirmación no coinciden" });
            }

            if (request.NewPassword.Length < 6)
            {
                return BadRequest(new { message = "La nueva contraseña debe tener al menos 6 caracteres" });
            }

            try
            {
                var user = await _userRepository.GetByIdAsync(userId);

                if (user == null)
                {
                    return NotFound(new { message = "Usuario no encontrado" });
                }

                // Verificar contraseña actual con BCrypt
                bool isValidPassword = BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.Password);

                if (!isValidPassword)
                {
                    return Unauthorized(new { message = "La contraseña actual es incorrecta" });
                }

                // Hash de nueva contraseña con BCrypt
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);

                // Actualizar contraseña
                user.Password = hashedPassword;
                await _userRepository.UpdateAsync(user);

                return Ok(new { message = "Contraseña actualizada con éxito" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Error al cambiar la contraseña", error = ex.Message });
            }
        }

        /// <summary>
        /// Genera una contraseña aleatoria segura con tipos de caracteres mezclados
        /// </summary>
        private string GenerarClaveSegura()
        {
            const string caracteresMinusculas = "abcdefghijklmnopqrstuvwxyz";
            const string caracteresMayusculas = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string caracteresNumeros = "0123456789";
            const string caracteresEspeciales = "!@#$%&*";
            const string todosCaracteres = caracteresMinusculas + caracteresMayusculas + caracteresNumeros + caracteresEspeciales;

            StringBuilder password = new StringBuilder();

            // Asegurar al menos un carácter de cada tipo
            password.Append(caracteresMinusculas[RandomNumberGenerator.GetInt32(caracteresMinusculas.Length)]);
            password.Append(caracteresMayusculas[RandomNumberGenerator.GetInt32(caracteresMayusculas.Length)]);
            password.Append(caracteresNumeros[RandomNumberGenerator.GetInt32(caracteresNumeros.Length)]);
            password.Append(caracteresEspeciales[RandomNumberGenerator.GetInt32(caracteresEspeciales.Length)]);

            // Completar hasta 12 caracteres
            for (int i = 4; i < 12; i++)
            {
                password.Append(todosCaracteres[RandomNumberGenerator.GetInt32(todosCaracteres.Length)]);
            }

            // Mezclar caracteres
            return new string(password.ToString().OrderBy(x => RandomNumberGenerator.GetInt32(1000)).ToArray());
        }
    }
}
