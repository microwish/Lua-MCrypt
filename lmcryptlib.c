#include <mcrypt.h>

#include <lua.h>//Lua 5.1.5
#include <lauxlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int module_open(lua_State *L)
{
  const char *algorithm, *algorithm_dir, *mode, *mode_dir;
	size_t l;

	if (lua_gettop(L) < 4)
		return luaL_error(L, "4 arguments required");

	//arg#1
	if (!(algorithm = lua_tostring(L, 1)))
		return luaL_error(L, "arg#1 invalid");

	//arg#2
	if (lua_isnoneornil(L, 2)) {
		algorithm_dir = NULL;
	} else {
		if (!(algorithm_dir = lua_tolstring(L, 2, &l)))
			return luaL_error(L, "arg#2 invalid");
		if (l == 0)
			algorithm_dir = NULL;
	}

	//arg#3
	if (!(mode = lua_tostring(L, 3)))
		return luaL_error(L, "arg#3 invalid");

	//arg#4
	if (lua_isnoneornil(L, 4)) {
			mode_dir = NULL;
	} else {
		if (!(mode_dir = lua_tolstring(L, 4, &l)))
			return luaL_error(L, "arg#4 invalid");
		if (l == 0)
			mode_dir = NULL;
	}

	MCRYPT *tdp;
	tdp = (MCRYPT *)lua_newuserdata(L, sizeof(MCRYPT));
	*tdp = mcrypt_module_open((char *)algorithm, (char *)algorithm_dir, (char *)mode, (char *)mode_dir);
	if (*tdp == MCRYPT_FAILED)
		return luaL_error(L, "mcrypt error");
	lua_rawseti(L, LUA_ENVIRONINDEX, 1);

	return 0;
}

static MCRYPT *retrieve_opened(lua_State *L)
{
	MCRYPT *tdp;

	lua_rawgeti(L, LUA_ENVIRONINDEX, 1);
	tdp = (MCRYPT *)lua_touserdata(L, -1);

	return tdp;
}

static int enc_get_key_size(lua_State *L)
{
	MCRYPT *tdp;
	int size;

	lua_rawgeti(L, LUA_ENVIRONINDEX, 1);
	if (!(tdp = (MCRYPT *)lua_touserdata(L, -1)))
		return luaL_error(L, "mcrypt failed");

	size = mcrypt_enc_get_key_size(*tdp);
	lua_pushinteger(L, (lua_Integer)size);

	return 1;
}

static int enc_get_iv_size(lua_State *L)
{
	MCRYPT *tdp;
	int size;

	lua_rawgeti(L, LUA_ENVIRONINDEX, 1);
	if (!(tdp = (MCRYPT *)lua_touserdata(L, -1)))
		return luaL_error(L, "mcrypt failed");

	size = mcrypt_enc_get_iv_size(*tdp);
	lua_pushinteger(L, (lua_Integer)size);

	return 1;
}

static int generic_init(lua_State *L)
{
	if (lua_gettop(L) < 2)
		return luaL_error(L, "2 argumetns required");

	char *key, *iv;
	size_t l;
	MCRYPT *tdp;

	//arg#1
	if (!(key = (char *)lua_tolstring(L, 1, &l)))
		return luaL_error(L, "arg#1 invalid");
	//TODO
	//check the length of key

	//arg#2
	if (!(iv = (char *)lua_tostring(L, 2)))
		return luaL_error(L, "arg#2 invalid");
	//TODO
	//check the length of IV 

	if(!(tdp = retrieve_opened(L)))
		return luaL_error(L, "mcrypt failed");

	if (mcrypt_generic_init(*tdp, (void *)key, (int)l, (void *)iv) < 0)
		return luaL_error(L, "mcrypt failed");

	return 0;
}

static int generic(lua_State *L)
{
	if (lua_gettop(L) < 1)
		luaL_error(L, "1 argument required");

	char *plain;
	size_t l;
	MCRYPT *tdp;

	if (!(plain = (char *)lua_tolstring(L, 1, &l)) || l < 1)
		luaL_error(L, "arg#1 invalid");
	//TODO
	//check the length of text according to different cipher mode

	if(!(tdp = retrieve_opened(L)))
		return luaL_error(L, "mcrypt failed");

	if(mcrypt_generic(*tdp, (void *)plain, (int)l))
		luaL_error(L, "mcrypt failed");
	lua_pushlstring(L, plain, l);

	return 1;
}

static int de_generic(lua_State *L)
{
	if (lua_gettop(L) < 1)
		luaL_error(L, "1 argument required");

	char *ciphered;
	size_t l;
	MCRYPT *tdp;

	if (!(ciphered = (char *)lua_tolstring(L, 1, &l)) || l < 1)
		luaL_error(L, "arg#1 invalied");
	//TODO
	//check the length of text according to different cipher mode

	if(!(tdp = retrieve_opened(L)))
		return luaL_error(L, "mcrypt failed");

	if (mdecrypt_generic(*tdp, (void *)ciphered, (int)l))
		luaL_error(L, "mcrypt failed");
	lua_pushlstring(L, ciphered, l);

	return 1;
}

static int generic_deinit(lua_State *L)
{
	MCRYPT *tdp;

	if(!(tdp = retrieve_opened(L)))
		return luaL_error(L, "mcrypt failed");

	if (mcrypt_generic_deinit(*tdp) < 0)
		luaL_error(L, "mcrypt failed");

	return 0;
}

static int module_close(lua_State *L)
{
	MCRYPT *tdp;

	if(!(tdp = retrieve_opened(L)))
		return luaL_error(L, "mcrypt failed");

	mcrypt_module_close(*tdp);

	return 0;
}

static const struct luaL_Reg mcrypt_lib[] = {
	{ "module_open", module_open },
	{ "enc_get_key_size", enc_get_key_size },
	{ "enc_get_iv_size", enc_get_iv_size },
	{ "generic_init", generic_init },
	{ "generic", generic },
	{ "de_generic", de_generic },
	{ "generic_deinit", generic_deinit },
	{ "module_close", module_close },
	{ NULL, NULL }
};

#define LUA_MCRYPTLIBNAME "mcrypt"

LUALIB_API int luaopen_mcrypt(lua_State *L)
{
	lua_createtable(L, 1, 0);
	lua_replace(L, LUA_ENVIRONINDEX);

	luaL_register(L, LUA_MCRYPTLIBNAME, mcrypt_lib);

	return 1;
}