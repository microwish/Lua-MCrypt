package.cpath = package.cpath .. ";/home/microwish/lua-mcrypt-baidu/lib/?.so"

local mcrypt = require("mcrypt")

--mcrypt.module_open("rijndael-128", "/home/microwish/lib/libmcrypt", "cfb", "/home/microwish/lib/libmcrypt")
mcrypt.module_open("rijndael-128", "", "cfb", "")
--mcrypt.module_open("rijndael-128", nil, "cfb", nil)

local key_size, iv_size = mcrypt.enc_get_key_size(), mcrypt.enc_get_iv_size()
print("this key size: " .. key_size, "this iv size: " .. iv_size)

mcrypt.generic_init("12345678poiuytre", "0987qwer0987qwer")
--mcrypt.generic_init("12345678poiuytre", "0987qwer")

local ciphered = mcrypt.generic("abcde")
--local ciphered = mcrypt.de_generic(string.char(93, 135, 253, 58, 142))
--local ciphered = mcrypt.de_generic(string.char(211, 113, 129, 171, 126))

print(string.byte(ciphered, 1, 5))

mcrypt.generic_deinit()

mcrypt.module_close()
