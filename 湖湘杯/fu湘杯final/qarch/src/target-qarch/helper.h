DEF_HELPER_4(uc_tracecode, void, i32, i32, ptr, i64)

DEF_HELPER_4(alu, void, env, i64, i64, i32)
DEF_HELPER_2(not, void, env, i64)
DEF_HELPER_2(pop, void, env, i64)
DEF_HELPER_2(push, void, env, i64)

DEF_HELPER_4(call, void, env, i64, i64, i32)
DEF_HELPER_1(ret, void, env)
DEF_HELPER_4(cmp, void, env, i64, i64, i32)
DEF_HELPER_4(j, void, env, i64, i64, i32)

DEF_HELPER_1(syscall, void, env)

DEF_HELPER_2(raise_exception, void, env, i32)
