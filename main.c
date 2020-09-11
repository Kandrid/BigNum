#include "bignum.h"
#include <time.h>

int main() {
	unsigned size = 1000000;
	float time;
	clock_t t1, t2;
	bignum_t n1, n2, n3;
	n1 = n2 = n3 = bn_default;

	char* str1 = (char*)malloc(size);
	char* str2 = (char*)malloc(size);

	while (scanf_s("%s%s", str1, size, str2, size)) {
		bn_set_str(&n1, str1);
		bn_set_str(&n2, str2);

		t1 = clock();
		int result = bn_div(&n1, &n2, &n3);
		t2 = clock();

		time = (float)(t2 - t1) / CLOCKS_PER_SEC;

		printf("%lfs\n", time);

		bn_free(&n1);
		bn_free(&n2);

		if (result) {
			printf("Error: %d\n", result);
		}
		else {
			printf("%s / %s\n", str1, str2);
			printf("Result: ");

			bn_print(&n3);
		}
	}

	bn_free(&n3);

	free(str1);
	free(str2);

	return 0;
}