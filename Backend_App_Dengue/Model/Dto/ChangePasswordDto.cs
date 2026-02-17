namespace Backend_App_Dengue.Model.Dto
{
    /// <summary>
    /// DTO para cambio de contraseña desde el perfil del usuario
    /// </summary>
    public class ChangePasswordDto
    {
        /// <summary>
        /// Contraseña actual del usuario
        /// </summary>
        public string CurrentPassword { get; set; }

        /// <summary>
        /// Nueva contraseña deseada
        /// </summary>
        public string NewPassword { get; set; }

        /// <summary>
        /// Confirmación de la nueva contraseña
        /// </summary>
        public string ConfirmPassword { get; set; }
    }
}
