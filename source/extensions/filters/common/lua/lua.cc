#include "source/extensions/filters/common/lua/lua.h"

#include <memory>

#include "envoy/common/exception.h"

#include "source/common/common/assert.h"
#include "source/common/common/lock_guard.h"
#include "source/common/common/thread.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace Lua {

Coroutine::Coroutine(const std::pair<lua_State*, lua_State*>& new_thread_state)
    : coroutine_state_(new_thread_state, false) {}

void Coroutine::start(int function_ref, int num_args, const std::function<void()>& yield_callback) {
  ASSERT(state_ == State::NotStarted);

  state_ = State::Yielded;
  lua_rawgeti(coroutine_state_.get(), LUA_REGISTRYINDEX, function_ref);
  ASSERT(lua_isfunction(coroutine_state_.get(), -1));

  // The function needs to come before the arguments but the arguments are already on the stack,
  // so we need to move it into position.
  lua_insert(coroutine_state_.get(), -(num_args + 1));
  resume(num_args, yield_callback);
}

void Coroutine::resume(int num_args, const std::function<void()>& yield_callback) {
  ASSERT(state_ == State::Yielded);
  lua_State *L = coroutine_state_.get();
  int rc = lua_resume(L, num_args);

  if (0 == rc) {
    state_ = State::Finished;
    ENVOY_LOG(debug, "coroutine finished");
  } else if (LUA_YIELD == rc) {
    state_ = State::Yielded;
    ENVOY_LOG(debug, "coroutine yielded");
    yield_callback();
  } else {
    state_ = State::Finished;
    const char* error = lua_tostring(L, -1);
    if (!error) {
      error = "unspecified lua error";
    }
    lua_getfield(L, LUA_GLOBALSINDEX, "debug");
    if (lua_istable(L, -1)) {
      lua_getfield(L, -1, "traceback");
      if (lua_isfunction(L, -1)) {
          lua_pushstring(L, error);  /* pass error message */
          lua_pushinteger(L, 0);  /* use 2 to skip this function and traceback */
          lua_call(L, 2, 1);  /* call debug.traceback */
          const char *tb = lua_tostring(L, -1);
          if (!tb) { tb = "traceback failed"; }
          ENVOY_LOG(error, tb);
      } else {
        lua_pop(L, 2);
     }
    } else {
        lua_pop(L, 1);
    }
    throw LuaException(error);
  }
}

ThreadLocalState::ThreadLocalState(const std::string& code, ThreadLocal::SlotAllocator& tls)
    : tls_slot_(ThreadLocal::TypedSlot<LuaThreadLocal>::makeUnique(tls)) {

  // First verify that the supplied code can be parsed.
  CSmartPtr<lua_State, lua_close> state(luaL_newstate());
  RELEASE_ASSERT(state.get() != nullptr, "unable to create new Lua state object");
  luaL_openlibs(state.get());

  if (0 != luaL_dostring(state.get(), code.c_str())) {
    throw LuaException(fmt::format("script load error: {}", lua_tostring(state.get(), -1)));
  }

  // Now initialize on all threads.
  tls_slot_->set([code](Event::Dispatcher&) { return std::make_shared<LuaThreadLocal>(code); });
}

int ThreadLocalState::getGlobalRef(uint64_t slot) {
  LuaThreadLocal& tls = **tls_slot_;
  ASSERT(tls.global_slots_.size() > slot);
  return tls.global_slots_[slot];
}

uint64_t ThreadLocalState::registerGlobal(const std::string& global,
                                          const InitializerList& initializers) {
  tls_slot_->runOnAllThreads([global, initializers](OptRef<LuaThreadLocal> tls) {
    lua_getglobal(tls->state_.get(), global.c_str());
    if (lua_isfunction(tls->state_.get(), -1)) {
      for (const auto& initialize : initializers) {
        initialize(tls->state_.get());
      }
      tls->global_slots_.push_back(luaL_ref(tls->state_.get(), LUA_REGISTRYINDEX));
    } else {
      ENVOY_LOG(debug, "definition for '{}' not found in script", global);
      lua_pop(tls->state_.get(), 1);
      tls->global_slots_.push_back(LUA_REFNIL);
    }
  });

  return current_global_slot_++;
}

CoroutinePtr ThreadLocalState::createCoroutine() {
  lua_State* state = tlsState().get();
  return std::make_unique<Coroutine>(std::make_pair(lua_newthread(state), state));
}

ThreadLocalState::LuaThreadLocal::LuaThreadLocal(const std::string& code)
    : state_(luaL_newstate()) {

  RELEASE_ASSERT(state_.get() != nullptr, "unable to create new Lua state object");
  luaL_openlibs(state_.get());
  int rc = luaL_dostring(state_.get(), code.c_str());
  ASSERT(rc == 0);
}

} // namespace Lua
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
