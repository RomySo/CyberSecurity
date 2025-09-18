import { simplePasswords } from "./simple-passwords.js";

function validatePassword(password) {
  const minLength = parseInt(process.env.PSWD_MIN_LENGTH, 10);
  const allowedChars = process.env.PSWD_ALLOWED_CHARS;
  const specialChars = process.env.PSWD_ALLOWED_CHARS.slice(-10);

  // Check if password length is sufficient
  if (password.length < minLength) {
    return {
      isValid: false,
      message: `Password must be at least ${minLength} characters long.`,
    };
  }

  // Check if password contains any common passwords (case insensitive and partial match check)
  const lowerCasePassword = password.toLowerCase();

  // Loop through the list of common passwords
  for (let i = 0; i < simplePasswords.length; i++) {
    // Check if the forbidden word exists as a part of the password
    if (lowerCasePassword.includes(simplePasswords[i])) {
      console.log(simplePasswords[i]);

      return {
        isValid: false,
        message: `Password must not contain common words or patterns like "${simplePasswords[i]}".`,
      };
    }
  }

  // Ensure the password contains required character types
  let containsUppercase = false;
  let containsDigit = false;
  let containsSpecialChar = false;

  for (const char of password) {
    if (char >= "A" && char <= "Z") containsUppercase = true;
    if (char >= "0" && char <= "9") containsDigit = true;
    if (specialChars.includes(char)) containsSpecialChar = true;

    // Check for invalid characters
    if (!allowedChars.includes(char)) {
      return {
        isValid: false,
        message: `Password contains an invalid character: "${char}". Only allowed characters are: ${allowedChars}`,
      };
    }
  }

  // Validate presence of character types
  if (!containsUppercase) {
    return {
      isValid: false,
      message: "Password must include at least one uppercase letter.",
    };
  }

  if (!containsDigit) {
    return {
      isValid: false,
      message: "Password must include at least one digit.",
    };
  }

  if (!containsSpecialChar) {
    return {
      isValid: false,
      message: `Password must include at least one special character from: ${specialChars}`,
    };
  }

  return {
    isValid: true,
    message: "Password is valid and meets all requirements.",
  };
}

export default validatePassword
