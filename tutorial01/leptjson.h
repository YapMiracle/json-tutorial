#ifndef LEPTJSON_H__
#define LEPTJSON_H__

typedef enum
{
    LEPT_NULL,
    LEPT_FALSE,
    LEPT_TRUE,
    LEPT_NUMBER,
    LEPT_STRING,
    LEPT_ARRAY,
    LEPT_OBJECT
} lept_type;//七种数据结构：NULL, false, true, number, string, array, object
//lept_type是一个enum lept_type，枚举型的
// typedef enum lept_type
// {
//     LEPT_NULL,
//     LEPT_FALSE,
//     LEPT_TRUE,
//     LEPT_NUMBER,
//     LEPT_STRING,
//     LEPT_ARRAY,
//     LEPT_OBJECT
// };
// 也可以使用这种写法

typedef struct
{
    lept_type type;
} lept_value;//结构体只有type一个成员

enum
{
    LEPT_PARSE_OK = 0,
    LEPT_PARSE_EXPECT_VALUE,
    LEPT_PARSE_INVALID_VALUE,
    LEPT_PARSE_ROOT_NOT_SINGULAR
};

int lept_parse(lept_value *v, const char *json);

lept_type lept_get_type(const lept_value *v);

#endif /* LEPTJSON_H__ */
