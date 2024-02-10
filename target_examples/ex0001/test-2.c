struct type_7;
struct type_1;
struct type_0;
struct type_4;
struct type_3;
struct type_6;
struct type_5;
struct type_2;

struct type_7 {
    struct type_2 *f0_type_7__type_2;
};

struct type_4 {
    struct type_6 *f0_type_4__type_6;
    struct type_5 *f1_type_4__type_5;
    struct type_3 *f2_type_4__type_3;
    struct type_1 *f3_type_4__type_1;
};

struct type_2 {
    struct type_3 *f0_type_2__type_3;
};

struct type_6 {
    struct type_0 *f0_type_6__type_0;
    struct type_0 *f1_type_6__type_0;
    struct type_5 *f2_type_6__type_5;
};

struct type_0 {
    struct type_4 *f0_type_0__type_4;
};

struct type_3 {
    struct type_6 *f0_type_3__type_6;
    struct type_5 *f1_type_3__type_5;
};


static void use_type_7_(struct type_7 *a)
{}
static void use_type_4_(struct type_4 *a)
{}
static void use_type_2_(struct type_2 *a)
{}
static void use_type_6_(struct type_6 *a)
{}
static void use_type_0_(struct type_0 *a)
{}
static void use_type_3_(struct type_3 *a)
{}

void use_type_7(void *a)
{
    use_type_7_(a);
    use_type_4_(a);
    use_type_2_(a);
    use_type_6_(a);
    use_type_0_(a);
    use_type_3_(a);
}
