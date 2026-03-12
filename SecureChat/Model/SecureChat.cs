using System.ComponentModel.DataAnnotations;

namespace SecureChat.Model
{

    public class SenderModel : IValidatableObject
    {
        [Required(ErrorMessage = "Plaintext is required.")]
        public string Plaintext { get; set; } = string.Empty;

        public string Key { get; set; } = string.Empty; // For symmetric techniques (Caesar, AES, etc.)
        public string? PublicKey { get; set; }     // Used when the technique is RSA (for encryption)
        public string? PrivateKey { get; set; }    // Possibly unused by the sender, or if you want to show both keys
        public string Technique { get; set; } = "Caesar";
        public string Ciphertext { get; set; } = string.Empty;
        public string ECCPrivateKey { get; set; } = "";
        public string ECCPublicKey { get; set; } = "";

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            // Only require the Key when technique is not OTP.
            if (Technique != "OTP" && string.IsNullOrWhiteSpace(Key))
            {
                yield return new ValidationResult("Key is required for the selected encryption technique.", new[] { nameof(Key) });
            }
        }
    }


    public class ReceiverModel : IValidatableObject
    {
        [Required(ErrorMessage = "Ciphertext is required.")]
        public string Ciphertext { get; set; } = string.Empty;

        [Required(ErrorMessage = "Key is required.")]
        public string Key { get; set; } = string.Empty; // For symmetric techniques
        public string? PublicKey { get; set; }  // Possibly unused by the receiver, or if you want to show both keys
        public string? PrivateKey { get; set; }  // Used when the technique is RSA (for decryption)
        public string Technique { get; set; } = "Caesar";
        public string Plaintext { get; set; } = string.Empty;
        public string ECCPrivateKey { get; set; } = "";
        public string ECCPublicKey { get; set; } = "";

        public string OriginalPlaintext { get; set; } = string.Empty;

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            // Only require the Key if the technique is not OTP.
            if (Technique != "OTP" && string.IsNullOrWhiteSpace(Key))
            {
                yield return new ValidationResult("Key is required for the selected decryption technique.", new[] { nameof(Key) });
            }
        }
    }

}


