# Hash Analyzer
require 'digest'
require 'base64'
require 'cgi'

WORD = "Try Decoding With Google Write:"
DE = "Decoder."

def hash_analyzer(hash)
  hash_length = hash.length

  case hash_length
  when 32
    puts "Type: MD5"
    puts "Length: #{hash_length} characters"
    puts "#{WORD} MD5 #{DE}"
  when 40
    puts "Type: SHA-1"
    puts "Length: #{hash_length} characters"
    puts "#{WORD} SHA-1 #{DE}"
  when 56
    if hash.match?(/^[a-f0-9]{56}$/i)
      puts "Type: SHA-224"
      puts "Length: #{hash_length} characters"
      puts "#{WORD} SHA-224 #{DE}"
    else
      puts "Type: Unknown"
    end
  when 64
    if hash.match?(/^[a-f0-9]{64}$/i)
      puts "Type: SHA-256"
      puts "Length: #{hash_length} characters"
      puts "#{WORD} SHA-256 #{DE}"
    elsif hash.match?(/^[a-f0-9]{40}$/i)
      puts "Type: SHA-1"
      puts "Length: #{hash_length} characters"
      puts "#{WORD} SHA-1 #{DE}"
    elsif hash.match?(/^[a-f0-9]{32}$/i)
      puts "Type: MD5"
      puts "Length: #{hash_length} characters"
      puts "#{WORD} MD5 #{DE}"
    else
      puts "Type: Unknown"
    end
  when 96
    if hash.match?(/^[a-f0-9]{96}$/i)
      puts "Type: SHA-384"
      puts "Length: #{hash_length} characters"
      puts "#{WORD} SHA-384 #{DE}"
    else
      puts "Type: Unknown"
    end
  when 128
    if hash.match?(/^[a-f0-9]{128}$/i)
      puts "Type: SHA-512"
      puts "Length: #{hash_length} characters"
      puts "#{WORD} SHA-512 #{DE}"
    else
      puts "Type: Unknown"
    end
  when 130
    if hash.match?(/^\$2[ayb]\$.{56}$/)
      puts "Type: bcrypt"
      puts "Length: #{hash_length} characters"
      puts "bcrypt is a salted hash function, not directly reversible."
    else
      puts "Type: Unknown"
    end
  when 144
    if hash.match?(/^\$5\$.{19}\$.{56}$/)
      puts "Type: SHA-256 Crypt"
      puts "Length: #{hash_length} characters"
      puts "SHA-256 Crypt is used in Unix-based systems for password hashing."
    else
      puts "Type: Unknown"
    end
  when 180
    if hash.match?(/^\$6\$.{8}\$.{86}$/)
      puts "Type: SHA-512 Crypt"
      puts "Length: #{hash_length} characters"
      puts "SHA-512 Crypt is used in Unix-based systems for password hashing."
    else
      puts "Type: Unknown"
    end
  when 192
    if hash.match?(/^[a-f0-9]{192}$/i)
      puts "Type: Whirlpool"
      puts "Length: #{hash_length} characters"
      puts "#{WORD} Whirlpool #{DE}"
    else
      puts "Type: Unknown"
    end
  when 256
    if hash.match?(/^[a-f0-9]{256}$/i)
      puts "Type: Hex"
      puts "Length: #{hash_length} characters"
      puts "#{WORD} Hex #{DE}"
      puts "but if you want https://www.convertstring.com/EncodeDecode/HexDecode"
    else
      puts "Type: Unknown"
    end
  else
    begin
      decoded_hash = Base64.strict_decode64(hash)
      puts "Type: Base64"
      puts "Length: #{hash_length} characters"
      puts "\e[38;2;153;51;179mDecoded Hash:\e[0m \e[38;2;102;255;102m#{decoded_hash}\e[0m"
    rescue ArgumentError
      if CGI.unescape(hash) != hash
        puts "Type: URL Hash"
        puts "Length: #{hash_length} characters"
        puts "#{WORD} URL Hash #{DE}"
      elsif CGI.unescapeHTML(hash) != hash
        puts "Type: HTML Hash"
        puts "Length: #{hash_length} characters"
        puts "#{WORD} HTML Hash #{DE}"
      else
        puts "Type: Unknown"
      end
    end
  end
end
color0 = "\e[0m"
color1 = "\e[38;2;204;102;255m"
color2 = "\e[38;2;255;255;102m"
acc = "\e[38;2;102;255;255mGithub: @Abo5"
system("clear")
puts "
                                                                                                                                                      
                                                                                             .---.                                                    
#{color2}     .                                .                                    _..._             |   |                             __.....__              
   .'|                              .'|                                  .'     '.           |   |.-.          .-          .-''         '.            
  <  |                             <  |                                 .   .-.   .          |   | \\ \\        / /         /     .-''''-.  `. .-,.--.  
   | |             __               | |         ,.----------.     __    |  '   '  |    __    |   |  \\ \\      / /         /     /________\\   \\|  .-. | 
   | | .'''-.   .:--.'.         _   | | .'''-. //            \\ .:--.'.  |  |   |  | .:--.'.  |   |   \\ \\    / /.--------.|                  || |  | | 
   | |/.'''. \\ / |   \\ |      .' |  | |/.'''. \\\\\\            // |   \\ | |  |   |  |/ |   \\ | |   |    \\ \\  / / |____    |\\    .-------------'| |  | | #{color0}
#{color1}   |  /    | | `' __ | |     .   | /|  /    | | `'----------' `' __ | | |  |   |  |' __ | | |   |     \\ `  /      /   /  \\    '-.____...---.| |  '-  
   | |     | |  .'.''| |   .'.'| |//| |     | |                .'.''| | |  |   |  |.'.''| | |   |      \\  /     .'   /    `.             .' | |      
   | |     | | / /   | |_.'.'.-'  / | |     | |               / /   | |_|  |   |  |/ /   | |_'---'      / /     /    /___    `''-...... -'   | |      
   | '.    | '.\\ \\._,\\ '/.'   \\_.'  | '.    | '.              \\ \\._,\\ '/|  |   |  |\\ \\._,\\ '/       |`-' /     |         |                   |_|      
   '---'   '---'`--'  `'            '---'   '---'              `--'  `' '--'   '--' `--'  `'         '..'      |_________|                            #{color0}
"

                                                                                                                                                  
puts "#{acc}"                                                                                                                                      
print "\nEnter the hash: "
user_input = gets.chomp
hash_analyzer(user_input)





=begin
مره بستفيد منه اذا ابي اللغة العربية او اللغة الانجليزية 

require 'digest'
require 'base64'
require 'cgi'

WORD_EN = "Try Decoding With Google Write:"
WORD_AR = "جرب فك التشفير مع جوجل رايت:"
DE_EN = "Decoder."
DE_AR = "فك التشفير."

def hash_analyzer(hash, language)
  hash_length = hash.length

  case hash_length
  when 32
    puts "Type: MD5"
    puts "Length: #{hash_length} characters"
    puts "#{language == 'ar' ? WORD_AR : WORD_EN} MD5 #{language == 'ar' ? DE_AR : DE_EN}"
  when 40
    puts "Type: SHA-1"
    puts "Length: #{hash_length} characters"
    puts "#{language == 'ar' ? WORD_AR : WORD_EN} SHA-1 #{language == 'ar' ? DE_AR : DE_EN}"
  when 56
    if hash.match?(/^[a-f0-9]{56}$/i)
      puts "Type: SHA-224"
      puts "Length: #{hash_length} characters"
      puts "#{language == 'ar' ? WORD_AR : WORD_EN} SHA-224 #{language == 'ar' ? DE_AR : DE_EN}"
    else
      puts "Type: Unknown"
    end
  when 64
    if hash.match?(/^[a-f0-9]{64}$/i)
      puts "Type: SHA-256"
      puts "Length: #{hash_length} characters"
      puts "#{language == 'ar' ? WORD_AR : WORD_EN} SHA-256 #{language == 'ar' ? DE_AR : DE_EN}"
    elsif hash.match?(/^[a-f0-9]{40}$/i)
      puts "Type: SHA-1"
      puts "Length: #{hash_length} characters"
      puts "#{language == 'ar' ? WORD_AR : WORD_EN} SHA-1 #{language == 'ar' ? DE_AR : DE_EN}"
    elsif hash.match?(/^[a-f0-9]{32}$/i)
      puts "Type: MD5"
      puts "Length: #{hash_length} characters"
      puts "#{language == 'ar' ? WORD_AR : WORD_EN} MD5 #{language == 'ar' ? DE_AR : DE_EN}"
    else
      puts "Type: Unknown"
    end
  when 96
    if hash.match?(/^[a-f0-9]{96}$/i)
      puts "Type: SHA-384"
      puts "Length: #{hash_length} characters"
      puts "#{language == 'ar' ? WORD_AR : WORD_EN} SHA-384 #{language == 'ar' ? DE_AR : DE_EN}"
    else
      puts "Type: Unknown"
    end
  when 128
    if hash.match?(/^[a-f0-9]{128}$/i)
      puts "Type: SHA-512"
      puts "Length: #{hash_length} characters"
      puts "#{language == 'ar' ? WORD_AR : WORD_EN} SHA-512 #{language == 'ar' ? DE_AR : DE_EN}"
    else
      puts "Type: Unknown"
    end
  when 130
    if hash.match?(/^\$2[ayb]\$.{56}$/)
      puts "Type: bcrypt"
      puts "Length: #{hash_length} characters"
      puts "bcrypt is a salted hash function, not directly reversible."
    else
      puts "Type: Unknown"
    end
  when 144
    if hash.match?(/^\$5\$.{19}\$.{56}$/)
      puts "Type: SHA-256 Crypt"
      puts "Length: #{hash_length} characters"
      puts "SHA-256 Crypt is used in Unix-based systems for password hashing."
    else
      puts "Type: Unknown"
    end
  when 180
    if hash.match?(/^\$6\$.{8}\$.{86}$/)
      puts "Type: SHA-512 Crypt"
      puts "Length: #{hash_length} characters"
      puts "SHA-512 Crypt is used in Unix-based systems for password hashing."
    else
      puts "Type: Unknown"
    end
  when 192
    if hash.match?(/^[a-f0-9]{192}$/i)
      puts "Type: Whirlpool"
      puts "Length: #{hash_length} characters"
      puts "#{language == 'ar' ? WORD_AR : WORD_EN} Whirlpool #{language == 'ar' ? DE_AR : DE_EN}"
    else
      puts "Type: Unknown"
    end
  when 256
    if hash.match?(/^[a-f0-9]{256}$/i)
      puts "Type: Hex"
      puts "Length: #{hash_length} characters"
      puts "#{language == 'ar' ? WORD_AR : WORD_EN} Hex #{language == 'ar' ? DE_AR : DE_EN}"
      puts "but if you want https://www.convertstring.com/EncodeDecode/HexDecode"
    else
      puts "Type: Unknown"
    end
  else
    begin
      decoded_hash = Base64.strict_decode64(hash)
      puts "Type: Base64"
      puts "Length: #{hash_length} characters"
      puts "\e[38;2;153;51;179mDecoded Hash:\e[0m \e[38;2;102;255;102m#{decoded_hash}\e[0m"
    rescue ArgumentError
      if CGI.unescape(hash) != hash
        puts "Type: URL Hash"
        puts "Length: #{hash_length} characters"
        puts "#{language == 'ar' ? WORD_AR : WORD_EN} URL Hash #{language == 'ar' ? DE_AR : DE_EN}"
      elsif CGI.unescapeHTML(hash) != hash
        puts "Type: HTML Hash"
        puts "Length: #{hash_length} characters"
        puts "#{language == 'ar' ? WORD_AR : WORD_EN} HTML Hash #{language == 'ar' ? DE_AR : DE_EN}"
      else
        puts "Type: Unknown"
      end
    end
  end
end

system("clear")
puts "
                                                                                      
\e[38;2;204;102;255m,--.                 ,--.                              ,--.                           
|  ,---. ,--,--.,---.|  ,---.      ,--,--,--,--, ,--,--|  ,--. ,--,-----.,---.,--.--. 
|  .-.  ' ,-.  (  .-'|  .-.  |    ' ,-.  |      ' ,-.  |  |\  '  /`-.  /| .-. |  .--' \e[0m
\e[38;2;255;255;102m|  | |  \ '-'  .-'  `|  | |  ,----\ '-'  |  ||  \ '-'  |  | \   '  /  `-\   --|  |
`--' `--'`--`--`----'`--' `--'----'`--`--`--''--'`--`--`--.-'  /  `-----'`----`--'    
                                                          `---'                       
                                \e[0m\e[38;2;102;255;255mGithub: @Abo5\e[0m"
print "Enter the hash: "
user_input = gets.chomp
print "Enter the language (ar/en): "
language = gets.chomp.downcase
hash_analyzer(user_input, language)

=end