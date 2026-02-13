#include <typeinfo>

struct Interface {
  virtual ~Interface() = default;
  virtual int value() const = 0;
};

struct Left : virtual Interface {
  int left_value = 11;
  int value() const override { return left_value; }
};

struct Right : virtual Interface {
  int right_value = 17;
  int value() const override { return right_value; }
};

struct Diamond : Left, Right {
  int diamond_value = 23;
  int value() const override { return Left::value() + Right::value() + diamond_value; }
};

struct PlainBase {
  virtual ~PlainBase() = default;
  virtual const char *name() const { return "PlainBase"; }
};

struct PlainDerived : PlainBase {
  const char *name() const override { return "PlainDerived"; }
};

static int type_name_byte(const std::type_info &ti) {
  return static_cast<unsigned char>(ti.name()[0]);
}

int main() {
  PlainBase *base = new PlainDerived();
  Interface *iface = new Diamond();

  int result = type_name_byte(typeid(*base));
  result += type_name_byte(typeid(*iface));
  result += base->name()[0];
  result += iface->value();

  delete base;
  delete iface;
  return result;
}
