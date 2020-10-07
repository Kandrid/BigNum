#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef unsigned char byte;

static inline void try(int result) {
	if (result) {
		printf("Error code %d\n", result);
		exit(EXIT_FAILURE);
	}
}

void print_bin(byte n) {
	for (int i = 0; i < 8; i++) {
		printf((n << i) & 128 ? "1" : "0");
	}
	printf(" ");
}

struct bignum_s {
	byte* data;
	size_t byte_count;
};

typedef struct bignum_s bignum_t;

const bignum_t bn_default = { NULL, 0 };

int is_numeric(const char* str) {
	for (size_t i = 0; i < strlen(str); i++) if (!((unsigned)str[i] - '0' < 10)) return 0;
	return 1;
}

size_t str_leading_zeroes(const char* str, size_t size) {
	size_t zeroes = 0;

	for (size_t i = 0; i < size; i++) {
		if (str[i] != '0' || i == size - 1) break;
		zeroes++;
	}

	return zeroes;
}

char* str_del_leading_zeroes(char* str, size_t* size) {
	size_t zeroes = str_leading_zeroes(str, *size);
	*size -= zeroes;
	return (char*)memmove(str, str + zeroes, *size + 1);
}

int str_halve(char* str, size_t* size) {
	if (is_numeric(str)) {
		int add = 0;

		for (size_t i = 0; i < *size; i++) {
			char digit = str[i] - '0';
			str[i] = ((digit >> 1) + add) + '0';
			add = (digit & 1) * 5;
		}

		if (!str_del_leading_zeroes(str, size)) return -2;
	}
	else return -1;

	return 0;
}

byte* str_to_bytes(const char* str, size_t* size) {
	byte* bytes = NULL;
	char* buffer = (char*)malloc(*size + 1);

	if (buffer) {
		if (!strcpy_s(buffer, *size + 1, str)) {
			size_t byte_count = 3;

			bytes = (byte*)calloc(byte_count, 1);

			if (bytes) {
				for (int i = 0; buffer[0] != '0' || strlen(buffer) > 1; i++) {
					if (i == 8) {
						i = 0;
						void* tmp = realloc(bytes, ++byte_count);

						if (tmp) {
							bytes = (byte*)tmp;
						}
						else {
							free(bytes);
							bytes = NULL;
							break;
						}

						bytes[byte_count - 1] = 0;
					}

					bytes[byte_count - 3] |= ((buffer[*size - 1] - '0') & 1) << i;
					str_halve(buffer, size);
				}

				*size = byte_count;
			}
		}

		free(buffer);
	}

	return bytes;
}

byte bn_last(bignum_t* n) {
	return n->data[n->byte_count - 1];
}

void bn_free(bignum_t* n) {
	if (n) {
		if (n->data) {
			free(n->data);
		}
		*n = bn_default;
	}
}

int bn_fix_signed(bignum_t* n) {
	if (n) {
		byte last = bn_last(n);
		size_t counter = 0;

		for (size_t i = n->byte_count - 1; i > 0 && n->data[i] == last; i--) counter++;

		if (counter != 2) {
			void* tmp = realloc(n->data, n->byte_count + 2 - counter);

			if (!tmp) return -2;

			size_t i = n->byte_count;

			n->data = (byte*)tmp;
			n->byte_count += 2 - counter;

			for (; i < n->byte_count; i++) n->data[i] = last;
		}
	}
	else return -1;

	return 0;
}

int bn_twos_comp(bignum_t* n) {
	if (n) {
		int carry = 1;
		for (size_t i = 0; i < n->byte_count; i++) {
			n->data[i] = ~n->data[i];

			for (int j = 0; j < 8 && carry; j++) {
				int bit = 1 << j;
				carry = n->data[i] & bit;
				n->data[i] = (n->data[i] & ~bit) | (~carry & bit);
			}
		}

		try(bn_fix_signed(n));
	}
	else return -1;

	return 0;
}

int bn_size_match(bignum_t* a, bignum_t* b) {
	bignum_t* big, * small;

	if (a->byte_count >= b->byte_count) {
		big = a;
		small = b;
	}
	else {
		big = b;
		small = a;
	}

	void* tmp = realloc(small->data, big->byte_count);

	if (!tmp) return -1;

	small->data = tmp;

	for (size_t i = small->byte_count; i < big->byte_count; i++) {
		small->data[i] = bn_last(small);
	}

	small->byte_count = big->byte_count;

	return 0;
}

int bn_set_str(bignum_t* num, char str_data[]) {
	char* str = str_data;
	_Bool negative = 0;

	bn_free(num);

	if (str_data[0] == '-') {
		negative = 1;
		str = str_data + 1;
	}

	if (is_numeric(str)) {
		num->byte_count = strlen(str);
		num->data = str_to_bytes(str, &(num->byte_count));
		if (!num->data) return -3;
		if (negative) try(bn_twos_comp(num));
	}
	else return -1;

	return 0;
}

int bn_print_bytes(bignum_t* n) {
	if (n) {
		for (size_t i = n->byte_count - 1; i != -1; i--) print_bin(n->data[i]);
		printf("\n");
	}
	else return -1;

	return 0;
}

int bn_copy(bignum_t* src, bignum_t* dest) {
	if (src && dest) {
		void* tmp = realloc(dest->data, src->byte_count);

		if (!tmp) return -2;

		tmp = memcpy(tmp, src->data, src->byte_count);

		if (!tmp) return -3;

		dest->data = tmp;
		dest->byte_count = src->byte_count;
	}
	else return -1;

	return 0;
}

_Bool bn_get_bit(bignum_t* n, size_t index) {
	if (index < n->byte_count * 8) return n->data[index / 8] & (1 << (index % 8));
	return 0;
}

int bn_set_bit(bignum_t* n, size_t index, _Bool value) {
	if (n && index < n->byte_count * 8) {
		byte bit = 1 << (index % 8);
		n->data[index / 8] = (n->data[index / 8] & ~bit) | (bit * value);
	}
	else return -1;

	return 0;
}

int bn_shiftr(bignum_t* n, size_t offset) {
	if (n) {
		for (size_t i = 0; i < (n->byte_count - 2) * 8; i++) {
			if (i + offset < (n->byte_count - 2) * 8) try(bn_set_bit(n, i, bn_get_bit(n, i + offset)));
			else try(bn_set_bit(n, i, 0));
		}

		try(bn_fix_signed(n));
	}
	else return -1;

	return 0;
}

int bn_shiftl(bignum_t* n, size_t offset) {
	if (n) {
		size_t byte_offset = (offset + 7) / 8;
		void* tmp = realloc(n->data, n->byte_count + byte_offset);

		if (!tmp) return -2;

		n->data = tmp;

		for (size_t i = 1; i <= byte_offset; i++) {
			n->data[n->byte_count + i - 1] = bn_last(n);
		}

		n->byte_count += byte_offset;

		for (size_t i = (n->byte_count - 2) * 8 - 1; i != -1; i--) try(bn_set_bit(n, i, bn_get_bit(n, i - offset)));

		try(bn_fix_signed(n));
	}
	else return -1;

	return 0;
}

_Bool bn_is_zero(bignum_t* n) {
	for (size_t i = 0; i < n->byte_count; i++) if (n->data[i]) return 0;

	return 1;
}

char* bn_to_str(bignum_t* n) {
	char* result = NULL;

	if (n) {
		if (bn_is_zero(n)) {
			result = (char*)malloc(2);

			if (result) {
				result[0] = '0';
				result[1] = '\0';
			}
		}
		else {
			_Bool negative = bn_last(n) == 0xFF;
			size_t digits = (size_t)ceil((n->byte_count - 2) * 8.0 * log10(2));
			result = (char*)malloc(digits + negative + 1);

			if (result) {
				size_t digit;
				bignum_t n0, n1;
				n0 = n1 = bn_default;

				result[digits + negative] = '\0';

				try(bn_copy(n, &n0));

				if (negative) try(bn_twos_comp(&n0));

				for (digit = 0; !bn_is_zero(&n0) && digit < digits; digit++) {
					int r = 0;

					try(bn_set_str(&n1, "0"));
					try(bn_size_match(&n0, &n1));

					for (size_t i = (n0.byte_count - 2) * 8 - 1; i != -1; i--) {
						r = 2 * r + bn_get_bit(&n0, i);
						try(bn_set_bit(&n1, i, r >= 10));
						r %= 10;
					}

					result[digit + negative] = r + '0';
					try(bn_copy(&n1, &n0));
				}

				bn_free(&n0);
				bn_free(&n1);

				result[digit + negative] = '\0';

				for (size_t i = 0; i < digit / 2; i++) {
					char tmp = result[i + negative];
					result[i + negative] = result[digit - i + negative - 1];
					result[digit - i + negative - 1] = tmp;
				}

				if (negative) result[0] = '-';
			}
		}
	}

	return result;
}

int bn_print(bignum_t* n) {
	if (n) {
		char* str = bn_to_str(n);

		if (!str) return -2;

		puts(str);

		free(str);
	}
	else return -1;

	return 0;
}

int bn_add(bignum_t* n1, bignum_t* n2, bignum_t* out) {
	if (n1 && n2 && out) {
		unsigned carry = 0;
		bignum_t big, small;
		big = small = bn_default;

		if (n1->byte_count >= n2->byte_count) {
			bn_copy(n1, &big);
			bn_copy(n2, &small);
		}
		else {
			bn_copy(n2, &big);
			bn_copy(n1, &small);
		}

		bn_free(out);

		void* tmp = realloc(out->data, big.byte_count);

		if (!tmp) return -2;

		out->data = (byte*)tmp;

		for (size_t i = out->byte_count; i < big.byte_count; i++) out->data[i] = bn_last(out);

		out->byte_count = big.byte_count;

		for (size_t i = 0; i < big.byte_count; i++) {
			unsigned sum = big.data[i] + carry;

			if (i < small.byte_count)
				sum += small.data[i];
			else
				sum += bn_last(&small);

			carry = sum >> 8;
			out->data[i] = sum & 0xFF;
		}

		try(bn_fix_signed(out));

		bn_free(&big);
		bn_free(&small);
	}
	else return -1;

	return 0;
}

int bn_sub(bignum_t* n1, bignum_t* n2, bignum_t* out) {
	try(bn_twos_comp(n2));
	try(bn_add(n1, n2, out));
	try(bn_twos_comp(n2));

	return 0;
}

int bn_inc(bignum_t* n) {
	if (n) {
		bignum_t one = bn_default;

		try(bn_set_str(&one, "1"));
		try(bn_add(n, &one, n));
	}
	else return -1;

	return 0;
}

int bn_dec(bignum_t* n) {
	if (n) {
		bignum_t one = bn_default;

		try(bn_set_str(&one, "1"));
		try(bn_sub(n, &one, n));
	}
	else return -1;

	return 0;
}

double bn_to_dbl(bignum_t* n) {
	_Bool negative = n->data[n->byte_count - 1];
	double result = 0;

	if (negative) try(bn_twos_comp(n));

	for (size_t i = 0; i < n->byte_count - 1; i++) result += (double)n->data[i] * pow(2, (double)i * 8.0);

	if (negative) {
		try(bn_twos_comp(n));
		result *= -1;
	}

	return result;
}

int bn_mul(bignum_t* n1, bignum_t* n2, bignum_t* out) {
	if (n1 && n2 && out) {
		_Bool negative = 0;
		int shifts = 0;
		bignum_t big, small;
		big = small = bn_default;

		if (n1->byte_count >= n2->byte_count) {
			try(bn_copy(n1, &big));
			try(bn_copy(n2, &small));
		}
		else {
			try(bn_copy(n2, &big));
			try(bn_copy(n1, &small));
		}

		bn_free(out);

		negative = (big.data[big.byte_count - 1] != small.data[small.byte_count - 1]);

		if (bn_last(&big) == 0xFF) try(bn_twos_comp(&big));
		if (bn_last(&small) == 0xFF) try(bn_twos_comp(&small));

		try(bn_set_str(out, "0"));

		for (size_t i = 0; i < (small.byte_count - 2) * 8; i++) {
			if (bn_get_bit(&small, i)) {
				try(bn_shiftl(&big, shifts));
				try(bn_add(out, &big, out));
				shifts = 1;
			}
			else shifts++;
		}

		if (negative) try(bn_twos_comp(out));

		bn_free(&big);
		bn_free(&small);
	}
	else return -1;

	return 0;
}

int bn_div(bignum_t* n1, bignum_t* n2, bignum_t* out) {
	if (n1 && n2 && out) {
		_Bool negative;
		bignum_t n, d, r, tmp;
		n = d = r = tmp = bn_default;

		if (bn_is_zero(n2)) return -2;

		try(bn_copy(n1, &n));
		try(bn_copy(n2, &d));

		bn_free(out);

		negative = (n.data[n.byte_count - 1] != d.data[d.byte_count - 1]);

		if (bn_last(&n) == 0xFF) try(bn_twos_comp(&n));
		if (bn_last(&d) == 0xFF) try(bn_twos_comp(&d));

		try(bn_set_str(&r, "0"));
		try(bn_set_str(out, "0"));
		try(bn_size_match(out, &n));

		for (size_t i = (n.byte_count - 2) * 8 - 1; i != -1; i--) {
			try(bn_shiftl(&r, 1));
			try(bn_set_bit(&r, 0, bn_get_bit(&n, i)));
			try(bn_sub(&r, &d, &tmp));

			if (!bn_last(&tmp)) {
				try(bn_copy(&tmp, &r));
				try(bn_set_bit(out, i, 1));
			}
		}

		if (negative) try(bn_twos_comp(out));

		try(bn_fix_signed(out));

		bn_free(&n);
		bn_free(&d);
		bn_free(&r);
		bn_free(&tmp);
	}
	else return -1;

	return 0;
}

int bn_pow(bignum_t* x, bignum_t* y, bignum_t* out) {
	if (x && y && out) {
		try(bn_set_str(out, "1"));

		if (bn_last(y) == 0xFF) try(bn_set_str(out, "0"));
		else while (!bn_is_zero(y)) {
			try(bn_mul(out, x, out));
			try(bn_dec(y));
		}
	}
	else return -1;

	return 0;
}

#endif