// TODO: maybe prolly DLL_THREAD_ATTACH/DETACH

#include <fstream>
#include <iostream>
#include <Windows.h>

#include <ldo.h>
#include <lgc.h>
#include <lapi.h>
#include <lfunc.h>
#include <lstate.h>
#include <lualib.h>
#include <Luau/Compiler.h>

namespace nula {
	constexpr uint8_t utag = 45; // n + u + l + a
	constexpr uint32_t signature = 0x616c756e;

	struct module {
		HANDLE fd;

		int ref;
		Closure* cl; 
	};

	int loadlib(lua_State* L) {
		const char* path = luaL_checkstring(L, 1);

		HANDLE fd = CreateFileA(
			path,
			GENERIC_READ, FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL
		);
		if (fd == INVALID_HANDLE_VALUE)
			return 0;

		uint32_t filesig;
		if (!ReadFile(fd, &filesig, 4, nullptr, nullptr) || filesig != signature)
			return 0;

		DWORD size = GetFileSize(fd, nullptr) - 4;
		std::string btc;
		btc.resize(size);

		SetFilePointer(fd, 4, NULL, FILE_BEGIN);
		if (!ReadFile(fd, btc.data(), size, nullptr, NULL))
			return 0;

		module* lib = (module*)lua_newuserdatatagged(L, sizeof(module), utag);
		memset(lib, 0, sizeof(module));

		if (luau_load(L, "", btc.data(), btc.size(), 0)) {
			CloseHandle(fd);
			return 0;
		}
		
		lib->cl = (Closure*)lua_topointer(L, -1);
		lib->ref = lua_ref(L, -1);
		lua_pop(L, 1);

		lua_getglobal(L, "GetProcAddress");
		lua_pushvalue(L, -2);
		lua_pushstring(L, "DllMain");
		lua_call(L, 2, 1);

		if (lua_isfunction(L, -1)) {
			lua_pushvalue(L, -2);
			lua_pushinteger(L, DLL_PROCESS_ATTACH);
			lua_pushboolean(L, false);
			lua_call(L, 3, 1);

			if (!lua_toboolean(L, -1)) {
				CloseHandle(fd);
				lua_unref(L, lib->ref);
				return 0;
			}
			lua_pop(L, 1);
		} else
			lua_pop(L, 1);

		return 1;
	}

	int gpa(lua_State* L) {
		size_t nameLen = 0;
		const char* name = luaL_checklstring(L, 2, &nameLen);
		module* lib = (module*)lua_touserdatatagged(L, 1, utag);
		if (!lib)
			luaL_typeerrorL(L, 1, "HMODULE");

		for (int i = 0; i < lib->cl->l.p->sizep; i++) {
			Proto* p = lib->cl->l.p->p[i];

			if (p->debugname && p->debugname->len == nameLen && !memcmp(getstr(p->debugname), name, nameLen)) {
				Closure* cl = luaF_newLclosure(L, 0, L->gt, p);
				setclvalue(L, L->top, cl);
				incr_top(L);

				return 1;
			}
		}

		return 0;
	}

	int freelib(lua_State* L) {
		module* lib = (module*)lua_touserdatatagged(L, 1, utag);

		lua_getglobal(L, "GetProcAddress");
		lua_pushvalue(L, -2);
		lua_pushstring(L, "DllMain");
		lua_call(L, 2, 1);

		if (lua_isfunction(L, -1)) {
			lua_pushvalue(L, -2);
			lua_pushinteger(L, DLL_PROCESS_DETACH);
			lua_pushboolean(L, false);
			lua_call(L, 3, 0);
		} else
			lua_pop(L, 1);

		CloseHandle(lib->fd);
		lua_unref(L, lib->ref);

		memset(lib, 0, sizeof(module));
		return 0;
	}

	void open(lua_State* L) {
		lua_pushcfunction(L, loadlib, "LoadLibrary");
		lua_setglobal(L, "LoadLibrary");

		lua_pushcfunction(L, gpa, "GetProcAddress");
		lua_setglobal(L, "GetProcAddress");

		lua_pushcfunction(L, freelib, "FreeLibrary");
		lua_setglobal(L, "FreeLibrary");

		lua_setuserdatadtor(L, utag, [](lua_State* L, void* ud) {
			module* lib = (module*)ud;

			lua_getglobal(L, "GetProcAddress");
			lua_pushvalue(L, -2);
			lua_pushstring(L, "DllMain");
			lua_call(L, 2, 1);

			if (lua_isfunction(L, -1)) {
				lua_pushvalue(L, -2);
				lua_pushinteger(L, DLL_PROCESS_DETACH);
				lua_pushboolean(L, true);
				lua_call(L, 3, 0);
			} else
				lua_pop(L, 1);

			CloseHandle(lib->fd);
			lua_unref(L, lib->ref);

			memset(lib, 0, sizeof(module));
		});
	}
}

static int handler(lua_State* L) {
	const char* arg = luaL_checkstring(L, 1);
	printf("%s\n", arg);
	printf("Stack Begin\n");
	lua_getglobal(L, "debug");
	lua_getfield(L, -1, "traceback");
	lua_call(L, 0, 1);
	const char* traceback = lua_tostring(L, -1);
	if (traceback)
		printf("%s", traceback);
	printf("Stack End\n");
	lua_pop(L, 2);
	return 0;
}

int main() {
	{
		const std::string& source = R"(
local function add(a, b)
	return a + b
end

local function DllMain(hinstDLL, fdwReason, lpvReserved)
	if fdwReason == 1 then
		print("attached to process")
	elseif fdwReason == 0 then
		if lpvReserved then
			print("detached by garbage collection")
		else
			print("detached by FreeLibrary")
		end
	end
	return true
end
)";
		const std::string& btc = Luau::compile(source, { 2, 1, 2 });

		std::fstream f("x64/Debug/example.nula", std::ios::binary | std::ios::out);
		f.write("nula", 4);
		f.write(btc.data(), btc.size());
		f.close();
	}

	const std::string& source = R"(
local module = LoadLibrary("x64/Debug/example.nula")
local add = GetProcAddress(module, "add")
print("result:", add(6, 7))
FreeLibrary(module)
)";
	const std::string& btc = Luau::compile(source, { 2, 1, 2 });
	
	lua_State* L = luaL_newstate();
	luaL_openlibs(L);
	nula::open(L);

	lua_pushcfunction(L, handler, "");
	if (luau_load(L, "module", btc.data(), btc.size(), 0)) {
		printf("%s\n", lua_tostring(L, -1));
		return 1;
	}

	lua_pcall(L, 0, 0, -2);

	return 0;
}
