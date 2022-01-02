#pragma once

#define evaluate_macro_1(...) __VA_ARGS__
#define evaluate_macro_2(...) evaluate_macro_1(evaluate_macro_1(__VA_ARGS__))
#define evaluate_macro_4(...) evaluate_macro_2(evaluate_macro_2(__VA_ARGS__))
#define evaluate_macro_8(...) evaluate_macro_4(evaluate_macro_4(__VA_ARGS__))
#define evaluate_macro_16(...) evaluate_macro_8(evaluate_macro_8(__VA_ARGS__))
#define evaluate_macro_many(...) evaluate_macro_16(evaluate_macro_16(evaluate_macro_16(evaluate_macro_16(__VA_ARGS__))))
#define empty_macro()
#define defer_macro_once(x) x empty_macro()

#define evaluate_for_each_inside(f, ...) \
    __VA_OPT__(evaluate_for_each_at_least_one(f, __VA_ARGS__))
#define evaluate_for_each_at_least_one(f, a, ...) \
    f a                                           \
            defer_macro_once(evaluate_for_each_again)()(f, __VA_ARGS__)
#define evaluate_for_each_again() evaluate_for_each_inside
#define evaluate_for_each(f, ...) evaluate_macro_many(evaluate_for_each_inside(f, __VA_ARGS__))


#define evaluate_for_each_comma_inside(f, ...) \
    __VA_OPT__(evaluate_for_each_comma_at_least_one(f, __VA_ARGS__))
#define evaluate_for_each_comma_starting_inside(f, ...) \
    __VA_OPT__(, evaluate_for_each_comma_at_least_one(f, __VA_ARGS__))
#define evaluate_for_each_comma_at_least_one(f, a, ...) \
    f a                                                 \
            defer_macro_once(evaluate_for_each_comma_starting)()(f, __VA_ARGS__)
#define evaluate_for_each_comma_starting() evaluate_for_each_comma_starting_inside
#define evaluate_for_each_comma(f, ...) evaluate_macro_many(evaluate_for_each_comma_inside(f, __VA_ARGS__))

#define evaluate_for_each_brackets_inside(f, ...) \
    __VA_OPT__(evaluate_for_each_brackets_at_least_one(f, __VA_ARGS__))
#define evaluate_for_each_brackets_at_least_one(f, a, ...) \
    f(a)                                                   \
            defer_macro_once(evaluate_for_each_brackets_again)()(f, __VA_ARGS__)
#define evaluate_for_each_brackets_again() evaluate_for_each_brackets_inside
#define evaluate_for_each_brackets(f, ...) evaluate_macro_many(evaluate_for_each_brackets_inside(f, __VA_ARGS__))


#define dbg_arg(arg) std::cout << " " << #arg << " = " << (arg);
#define dbg(...)                                                         \
    do {                                                                 \
        std::cout << __FILE__ << ":" << __LINE__ << ": " << __FUNCTION__; \
        evaluate_for_each_brackets(dbg_arg, __VA_ARGS__);                \
        std::cout << std::endl;                                          \
    } while (0)
