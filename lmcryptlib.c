#include <mcrypt.h>

#include <lua.h>//Lua 5.1.5
#include <lauxlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef MCRYPT (*ModuleOpenFunc)(char *, char *, char *, char *);
typedef int (*GenericInitFunc)(MCRYPT, void *, int, void *);
typedef int (*GenericFunc)(MCRYPT, void *, int);
typedef int (*OneArgFunc)(MCRYPT);

static int td_ref = 1;

static void *mcrypt_lib_handler = NULL;

#define DL_MCRYPT_LIB \
	do { \
		if (!mcrypt_lib_handler) { \
			if (!(mcrypt_lib_handler = \
						dlopen("/home/work/lib/libmcrypt/lib/libmcrypt.so", RTLD_LAZY))) \
				luaL_error(L, "Loading MCrypt lib failed"); \
		} \
	} while (0)

#define DL_MCRYPT_DEREF \
	do { \
		if (mcrypt_lib_handler) { \
			dlclose(mcrypt_lib_handler); \
		} \
	} while (0)

//static ModuleOpenFunc module_open_func = NULL;
//static GenericInitFunc generic_init_func = NULL;
//static GenericFunc generic_func = NULL, de_generic_func = NULL;
static OneArgFunc get_key_size_func = NULL,
					get_iv_size_func = NULL,
					get_block_size_func = NULL,
					generic_deinit_func = NULL,
					is_block_mode_func = NULL;

enum {
	MCRYPT_GENERIC_DEINIT_FUNC = 0,
	MCRYPT_ENC_GET_KEY_SIZE_FUNC,
	MCRYPT_ENC_GET_IV_SIZE_FUNC,
	MCRYPT_ENC_GET_BLOCK_SIZE_FUNC,
	MCRYPT_ENC_IS_BLOCK_MODE_FUNC
};

static const char *mcrypt_funcs[] = {
	"mcrypt_generic_deinit",
	"mcrypt_enc_get_key_size",
	"mcrypt_enc_get_iv_size",
	"mcrypt_enc_get_block_size",
	"mcrypt_enc_is_block_mode"
};

//TODO
//error processing
#define DL_MCRYPT_FUNC(func_id) \
	do { \
		switch (func_id) { \
			case MCRYPT_GENERIC_DEINIT_FUNC: \
				if (!generic_deinit_func) { \
					generic_deinit_func = (OneArgFunc)dlsym(mcrypt_lib_handler, mcrypt_funcs[func_id]); \
				} \
				break; \
			case MCRYPT_ENC_GET_KEY_SIZE_FUNC: \
				if (!get_key_size_func) { \
					get_key_size_func = (OneArgFunc)dlsym(mcrypt_lib_handler, mcrypt_funcs[func_id]); \
				} \
				break; \
			case MCRYPT_ENC_GET_IV_SIZE_FUNC: \
				if (!get_iv_size_func) { \
					get_iv_size_func = (OneArgFunc)dlsym(mcrypt_lib_handler, mcrypt_funcs[func_id]); \
				} \
				break; \
			case MCRYPT_ENC_GET_BLOCK_SIZE_FUNC: \
				if (!get_block_size_func) { \
					get_block_size_func = (OneArgFunc)dlsym(mcrypt_lib_handler, mcrypt_funcs[func_id]); \
				} \
				break; \
			case MCRYPT_ENC_IS_BLOCK_MODE_FUNC: \
				if (!is_block_mode_func) { \
					is_block_mode_func = (OneArgFunc)dlsym(mcrypt_lib_handler, mcrypt_funcs[func_id]); \
				} \
				break; \
		} \
	} while (0)


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

	MCRYPT *tdp = (MCRYPT *)lua_newuserdata(L, sizeof(MCRYPT));

	DL_MCRYPT_LIB;

	//TODO
	//error processing
	ModuleOpenFunc module_open_func = dlsym(mcrypt_lib_handler, "mcrypt_module_open");

	*tdp = module_open_func((char *)algorithm, (char *)algorithm_dir, (char *)mode, (char *)mode_dir);
	if (*tdp == MCRYPT_FAILED) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "Could not open encryption module");
	}
	td_ref = luaL_ref(L, LUA_ENVIRONINDEX);

	return 0;
}

#define RETRIEVE_TD(L, tdp) \
	do { \
		lua_rawgeti(L, LUA_ENVIRONINDEX, td_ref); \
		tdp = (MCRYPT *)lua_touserdata(L, -1); \
		if (!tdp) \
			luaL_error(L, "Must open MCrypt module first"); \
		lua_pop(L, 1); \
	} while (0)

static int enc_get_key_size(lua_State *L)
{
	MCRYPT *tdp;
	int size;

	RETRIEVE_TD(L, tdp);

	DL_MCRYPT_LIB;

	DL_MCRYPT_FUNC(MCRYPT_ENC_GET_KEY_SIZE_FUNC);

	size = get_key_size_func(*tdp);
	lua_pushinteger(L, (lua_Integer)size);

	return 1;
}

static int enc_get_iv_size(lua_State *L)
{
	MCRYPT *tdp;
	int size;

	RETRIEVE_TD(L, tdp);

	DL_MCRYPT_LIB;

	DL_MCRYPT_FUNC(MCRYPT_ENC_GET_IV_SIZE_FUNC);

	size = get_iv_size_func(*tdp);
	lua_pushinteger(L, (lua_Integer)size);

	return 1;
}

static int generic_init(lua_State *L)
{
	if (lua_gettop(L) < 2) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "2 argumetns required");
	}

	MCRYPT *tdp;
	char *key, *iv, *iv_s;
	size_t key_len;
	int key_size, iv_size;

	//arg#1
	if (!(key = (char *)lua_tolstring(L, 1, &key_len))) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "arg#1 invalid");
	}

	//arg#2
	if (!(iv = (char *)lua_tostring(L, 2))) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "arg#2 invalid");
	}

	RETRIEVE_TD(L, tdp);

	DL_MCRYPT_LIB;

	DL_MCRYPT_FUNC(MCRYPT_ENC_GET_KEY_SIZE_FUNC);

	key_size = get_key_size_func(*tdp);
	if (key_len > (size_t)key_size) {
		key_len = (size_t)key_size;
	}

	DL_MCRYPT_FUNC(MCRYPT_ENC_GET_IV_SIZE_FUNC);

	iv_size = get_iv_size_func(*tdp);
	if (iv_size <= 0) {
		iv_s = NULL;
	} else {
		if (!(iv_s = calloc(iv_size + 1, sizeof(char)))) {
			DL_MCRYPT_DEREF;
			return luaL_error(L, "Could not alloc IV");
		}
		memcpy(iv_s, iv, iv_size);
	}

	DL_MCRYPT_FUNC(MCRYPT_GENERIC_DEINIT_FUNC);
	generic_deinit_func(*tdp);

	//TODO
	//error processing
	GenericInitFunc generic_init_func = dlsym(mcrypt_lib_handler, "mcrypt_generic_init");

	//TODO
	//tell more specific errors according to returned codes
	if (generic_init_func(*tdp, (void *)key, (int)key_len, (void *)iv_s) < 0) {
		free(iv_s);
		DL_MCRYPT_DEREF;
		return luaL_error(L, "MCrypt generic init failed");
	}
	free(iv_s);

	return 0;
}

static int generic(lua_State *L)
{
	if (lua_gettop(L) < 1) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "1 argument required");
	}

	char *plain;
	size_t l;
	MCRYPT *tdp;

	if (!(plain = (char *)lua_tolstring(L, 1, &l)) || l == 0) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "arg#1 invalid");
	}

	RETRIEVE_TD(L, tdp);

	DL_MCRYPT_LIB;

	//TODO
	//error processing
	GenericFunc generic_func = dlsym(mcrypt_lib_handler, "mcrypt_generic");

	DL_MCRYPT_FUNC(MCRYPT_ENC_IS_BLOCK_MODE_FUNC);
	if (is_block_mode_func(*tdp) == 1) {
		DL_MCRYPT_FUNC(MCRYPT_ENC_GET_BLOCK_SIZE_FUNC);
		int block_size = get_block_size_func(*tdp);
		int data_size = ((l - 1) / block_size + 1) * block_size;
		char *plain_s = calloc(data_size + 1, sizeof(char));
		if (!plain_s) {
			DL_MCRYPT_DEREF;
			return luaL_error(L, "Cloud not align block");
		}
		memcpy(plain_s, plain, l);

		if(generic_func(*tdp, (void *)plain_s, data_size)) {
			free(plain_s);
			DL_MCRYPT_DEREF;
			return luaL_error(L, "MCrypt generic failed");
		}
		lua_pushlstring(L, plain_s, (size_t)data_size);
		free(plain_s);
	} else {
		if(generic_func(*tdp, (void *)plain, (int)l)) {
			DL_MCRYPT_DEREF;
			return luaL_error(L, "MCrypt generic failed");
		}
		lua_pushlstring(L, plain, l);
	}

	return 1;
}

static int de_generic(lua_State *L)
{
	if (lua_gettop(L) < 1) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "1 argument required");
	}

	char *ciphered;
	size_t l;
	MCRYPT *tdp;

	if (!(ciphered = (char *)lua_tolstring(L, 1, &l)) || l < 1) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "arg#1 invalied");
	}

	RETRIEVE_TD(L, tdp);

	DL_MCRYPT_LIB;

	//TODO
	//error processing
	GenericFunc de_generic_func = dlsym(mcrypt_lib_handler, "mdecrypt_generic");

	DL_MCRYPT_FUNC(MCRYPT_ENC_IS_BLOCK_MODE_FUNC);
	if (is_block_mode_func(*tdp) == 1) {
		DL_MCRYPT_FUNC(MCRYPT_ENC_GET_BLOCK_SIZE_FUNC);
		int block_size = get_block_size_func(*tdp);
		int data_size = ((l - 1) / block_size + 1) * block_size;
		char *ciphered_s = calloc(data_size + 1, sizeof(char));
		if (!ciphered_s) {
			DL_MCRYPT_DEREF;
			return luaL_error(L, "Cloud not align block");
		}
		memcpy(ciphered_s, ciphered, l);

		if(de_generic_func(*tdp, (void *)ciphered_s, data_size)) {
			free(ciphered_s);
			DL_MCRYPT_DEREF;
			return luaL_error(L, "MCrypt de-generic failed");
		}
		lua_pushlstring(L, ciphered_s, (size_t)data_size);
		free(ciphered_s);
	} else {
		if (de_generic_func(*tdp, (void *)ciphered, (int)l)) {
			DL_MCRYPT_DEREF;
			return luaL_error(L, "MCrypt de-generic failed");
		}
		lua_pushlstring(L, ciphered, l);
	}

	return 1;
}

static int generic_deinit(lua_State *L)
{
	MCRYPT *tdp;

	RETRIEVE_TD(L, tdp);

	DL_MCRYPT_LIB;

	DL_MCRYPT_FUNC(MCRYPT_GENERIC_DEINIT_FUNC);

	if (generic_deinit_func(*tdp) < 0) {
		DL_MCRYPT_DEREF;
		return luaL_error(L, "Could not terminate encryption specifier");
	}

	return 0;
}

static int module_close(lua_State *L)
{
	MCRYPT *tdp;

	RETRIEVE_TD(L, tdp);

	DL_MCRYPT_LIB;

	//TODO
	//error processing
	OneArgFunc module_close_func = dlsym(mcrypt_lib_handler, "mcrypt_module_close");

	module_close_func(*tdp);

	luaL_unref(L, LUA_ENVIRONINDEX, td_ref);

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
