#include <stdio.h>
#include <stdlib.h>

int add(int a, int b) { return a + b; }

int multiply(int x, int y) { return x * y; }

int main(int argc, char *argv[]) {
  printf("Test program\n");
  int result = add(5, 3);
  result = multiply(result, 2);
  printf("Result: %d\n", result);
  return 0;
}
