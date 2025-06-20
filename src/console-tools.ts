export async function getPassword(prompt: string): Promise<string> {
    return new Promise((resolve) => {
      process.stdout.write(prompt);
      
      const stdin = process.stdin;
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding('utf8'); // Important for correct UTF-8 handling
      
      let password = '';
      
      const handleInput = (input: string) => {
        for (let i = 0; i < input.length; i++) {
          const char = input[i];
          const charCode = char.charCodeAt(0);
          
          if (charCode === 13 || charCode === 10) { // Enter
            stdin.setRawMode(false);
            stdin.pause();
            stdin.removeListener('data', handleInput);
            process.stdout.write('\n');
            resolve(password);
            return;
          }
          
          if (charCode === 127 || charCode === 8) { // Backspace
            if (password.length > 0) {
              password = password.substring(0, password.length - 1);
              process.stdout.write('\b \b');
            }
          } else if (charCode === 3) { // Ctrl+C
            stdin.setRawMode(false);
            stdin.pause();
            stdin.removeListener('data', handleInput);
            process.stdout.write('\n');
            process.exit(0);
          } else if (isPrintableChar(char)) {
            password += char;
            process.stdout.write('*');
          }
        }
      };
      
      stdin.on('data', handleInput);
    });
  }
  
function isPrintableChar(char: string): boolean {
    const code = char.charCodeAt(0);
    
    // ASCII printable characters
    if (code >= 32 && code <= 126) {
      return true;
    }
    
    // Cyrillic (Russian alphabet)
    if (code >= 0x0400 && code <= 0x04FF) {
      return true;
    }
    
    // Additional Unicode categories for other languages
    // Latin extensions
    if (code >= 0x00C0 && code <= 0x017F) {
      return true;
    }
    
    // You can add other ranges as needed
    // For example, for Chinese: code >= 0x4E00 && code <= 0x9FFF
    // For Arabic: code >= 0x0600 && code <= 0x06FF
    
    return false;
  }