struct type_7;
struct type_1;
struct type_0;
struct type_4;
struct type_3;
struct type_6;
struct type_5;
struct type_2;

struct type_0 {
    struct type_4 *f0_type_0__type_4;
};

struct type_1 {
    struct type_7 *f0_type_1__type_7;
    struct type_1 *f1_type_1__type_1;
};

struct type_5 {
    struct type_0 *f0_type_5__type_0;
    struct type_7 *f1_type_5__type_7;
};

struct type_4 {
    struct type_6 *f0_type_4__type_6;
    struct type_5 *f1_type_4__type_5;
    struct type_3 *f2_type_4__type_3;
    struct type_1 *f3_type_4__type_1;
};

struct type_6 {
    struct type_0 *f0_type_6__type_0;
    struct type_0 *f1_type_6__type_0;
    struct type_5 *f2_type_6__type_5;
};

struct type_3 {
    struct type_6 *f0_type_3__type_6;
    struct type_5 *f1_type_3__type_5;
};

struct type_7 {
    struct type_2 *f0_type_7__type_2;
};


static void use_type_0_(struct type_0 *a)
{}
static void use_type_1_(struct type_1 *a)
{}
static void use_type_5_(struct type_5 *a)
{}
static void use_type_4_(struct type_4 *a)
{}
static void use_type_6_(struct type_6 *a)
{}
static void use_type_3_(struct type_3 *a)
{}
static void use_type_7_(struct type_7 *a)
{}

void use_type_0(void *a)
{
    use_type_0_(a);
    use_type_1_(a);
    use_type_5_(a);
    use_type_4_(a);
    use_type_6_(a);
    use_type_3_(a);
    use_type_7_(a);
}
