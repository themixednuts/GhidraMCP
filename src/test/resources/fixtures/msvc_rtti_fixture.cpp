#include <typeinfo>

struct Interface {
  virtual ~Interface() = default;
  virtual int value() const = 0;
};

struct Left : virtual Interface {
  int leftValue = 11;
  int value() const override { return leftValue; }
};

struct Right : virtual Interface {
  int rightValue = 17;
  int value() const override { return rightValue; }
};

struct Diamond : Left, Right {
  int diamondValue = 23;
  int value() const override { return Left::value() + Right::value() + diamondValue; }
};

struct PlainBase {
  virtual ~PlainBase() = default;
  virtual const char *name() const { return "PlainBase"; }
};

struct PlainDerived : PlainBase {
  const char *name() const override { return "PlainDerived"; }
};

static int typeNameByte(const std::type_info &ti) {
  return static_cast<unsigned char>(ti.name()[0]);
}

int main() {
  PlainBase *base = new PlainDerived();
  Interface *iface = new Diamond();

  int result = typeNameByte(typeid(*base));
  result += typeNameByte(typeid(*iface));
  result += base->name()[0];
  result += iface->value();

  delete base;
  delete iface;
  return result;
}
