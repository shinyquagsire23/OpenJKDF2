// From: https://github.com/eteran/cpp-utilities/blob/master/fixed/include/cpp-utilities/fixed.h
// See also: http://stackoverflow.com/questions/79677/whats-the-best-way-to-do-fixed-point-math
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Evan Teran
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef FIXED_H_
#define FIXED_H_

#if __cplusplus >= 201402L
#define CONSTEXPR14 constexpr
#else
#define CONSTEXPR14
#endif

#include <cstddef> // for size_t
#include <cstdint>
#include <exception>
#include <ostream>
#include <type_traits>

namespace numeric {

template <size_t I, size_t F>
class fixed;

namespace detail {

// helper templates to make magic with types :)
// these allow us to determine reasonable types from
// a desired size, they also let us infer the next largest type
// from a type which is nice for the division op
template <size_t T>
struct type_from_size {
	using value_type                     = void;
	using unsigned_type                  = void;
	using signed_type                    = void;
	static constexpr bool is_specialized = false;
};

#if defined(__GNUC__) && defined(__x86_64__) && !defined(__STRICT_ANSI__)
template <>
struct type_from_size<128> {
	static constexpr bool is_specialized = true;
	static constexpr size_t size         = 128;

	using value_type    = __int128;
	using unsigned_type = unsigned __int128;
	using signed_type   = __int128;
	using next_size     = type_from_size<256>;
};
#endif

template <>
struct type_from_size<64> {
	static constexpr bool is_specialized = true;
	static constexpr size_t size         = 64;

	using value_type    = int64_t;
	using unsigned_type = std::make_unsigned<value_type>::type;
	using signed_type   = std::make_signed<value_type>::type;
	using next_size     = type_from_size<128>;
};

template <>
struct type_from_size<32> {
	static constexpr bool is_specialized = true;
	static constexpr size_t size         = 32;

	using value_type    = int32_t;
	using unsigned_type = std::make_unsigned<value_type>::type;
	using signed_type   = std::make_signed<value_type>::type;
	using next_size     = type_from_size<64>;
};

template <>
struct type_from_size<16> {
	static constexpr bool is_specialized = true;
	static constexpr size_t size         = 16;

	using value_type    = int16_t;
	using unsigned_type = std::make_unsigned<value_type>::type;
	using signed_type   = std::make_signed<value_type>::type;
	using next_size     = type_from_size<32>;
};

template <>
struct type_from_size<8> {
	static constexpr bool is_specialized = true;
	static constexpr size_t size         = 8;

	using value_type    = int8_t;
	using unsigned_type = std::make_unsigned<value_type>::type;
	using signed_type   = std::make_signed<value_type>::type;
	using next_size     = type_from_size<16>;
};

// this is to assist in adding support for non-native base
// types (for adding big-int support), this should be fine
// unless your bit-int class doesn't nicely support casting
template <class B, class N>
constexpr B next_to_base(N rhs) {
	return static_cast<B>(rhs);
}

struct divide_by_zero : std::exception {
};

template <size_t I, size_t F>
CONSTEXPR14 fixed<I, F> divide(fixed<I, F> numerator, fixed<I, F> denominator, fixed<I, F> &remainder, typename std::enable_if<type_from_size<I + F>::next_size::is_specialized>::type * = nullptr) {

	using next_type                  = typename fixed<I, F>::next_type;
	using base_type                  = typename fixed<I, F>::base_type;
	constexpr size_t fractional_bits = fixed<I, F>::fractional_bits;

	next_type t(numerator.to_raw());
	t <<= fractional_bits;

	fixed<I, F> quotient;

	quotient  = fixed<I, F>::from_base(next_to_base<base_type>(t / denominator.to_raw()));
	remainder = fixed<I, F>::from_base(next_to_base<base_type>(t % denominator.to_raw()));

	return quotient;
}

template <size_t I, size_t F>
CONSTEXPR14 fixed<I, F> divide(fixed<I, F> numerator, fixed<I, F> denominator, fixed<I, F> &remainder, typename std::enable_if<!type_from_size<I + F>::next_size::is_specialized>::type * = nullptr) {

	using unsigned_type = typename fixed<I, F>::unsigned_type;

	constexpr int bits = fixed<I, F>::total_bits;

	if (denominator == 0) {
		throw divide_by_zero();
	} else {

		int sign = 0;

		fixed<I, F> quotient;

		if (numerator < 0) {
			sign ^= 1;
			numerator = -numerator;
		}

		if (denominator < 0) {
			sign ^= 1;
			denominator = -denominator;
		}

		unsigned_type n      = numerator.to_raw();
		unsigned_type d      = denominator.to_raw();
		unsigned_type x      = 1;
		unsigned_type answer = 0;

		// egyptian division algorithm
		while ((n >= d) && (((d >> (bits - 1)) & 1) == 0)) {
			x <<= 1;
			d <<= 1;
		}

		while (x != 0) {
			if (n >= d) {
				n -= d;
				answer += x;
			}

			x >>= 1;
			d >>= 1;
		}

		unsigned_type l1 = n;
		unsigned_type l2 = denominator.to_raw();

		// calculate the lower bits (needs to be unsigned)
		while (l1 >> (bits - F) > 0) {
			l1 >>= 1;
			l2 >>= 1;
		}
		const unsigned_type lo = (l1 << F) / l2;

		quotient  = fixed<I, F>::from_base((answer << F) | lo);
		remainder = n;

		if (sign) {
			quotient = -quotient;
		}

		return quotient;
	}
}

// this is the usual implementation of multiplication
template <size_t I, size_t F>
CONSTEXPR14 fixed<I, F> multiply(fixed<I, F> lhs, fixed<I, F> rhs, typename std::enable_if<type_from_size<I + F>::next_size::is_specialized>::type * = nullptr) {

	using next_type = typename fixed<I, F>::next_type;
	using base_type = typename fixed<I, F>::base_type;

	constexpr size_t fractional_bits = fixed<I, F>::fractional_bits;

	next_type t(static_cast<next_type>(lhs.to_raw()) * static_cast<next_type>(rhs.to_raw()));
	t >>= fractional_bits;

	return fixed<I, F>::from_base(next_to_base<base_type>(t));
}

// this is the fall back version we use when we don't have a next size
// it is slightly slower, but is more robust since it doesn't
// require and upgraded type
template <size_t I, size_t F>
CONSTEXPR14 fixed<I, F> multiply(fixed<I, F> lhs, fixed<I, F> rhs, typename std::enable_if<!type_from_size<I + F>::next_size::is_specialized>::type * = nullptr) {

	using base_type = typename fixed<I, F>::base_type;

	constexpr size_t fractional_bits    = fixed<I, F>::fractional_bits;
	constexpr base_type integer_mask    = fixed<I, F>::integer_mask;
	constexpr base_type fractional_mask = fixed<I, F>::fractional_mask;

	// more costly but doesn't need a larger type
	const base_type a_hi = (lhs.to_raw() & integer_mask) >> fractional_bits;
	const base_type b_hi = (rhs.to_raw() & integer_mask) >> fractional_bits;
	const base_type a_lo = (lhs.to_raw() & fractional_mask);
	const base_type b_lo = (rhs.to_raw() & fractional_mask);

	const base_type x1 = a_hi * b_hi;
	const base_type x2 = a_hi * b_lo;
	const base_type x3 = a_lo * b_hi;
	const base_type x4 = a_lo * b_lo;

	return fixed<I, F>::from_base((x1 << fractional_bits) + (x3 + x2) + (x4 >> fractional_bits));
}
}

template <size_t I, size_t F>
class fixed {
	static_assert(detail::type_from_size<I + F>::is_specialized, "invalid combination of sizes");

public:
	static constexpr size_t fractional_bits = F;
	static constexpr size_t integer_bits    = I;
	static constexpr size_t total_bits      = I + F;

	using base_type_info = detail::type_from_size<total_bits>;

	using base_type     = typename base_type_info::value_type;
	using next_type     = typename base_type_info::next_size::value_type;
	using unsigned_type = typename base_type_info::unsigned_type;

public:
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
#endif
	static constexpr base_type fractional_mask = ~(static_cast<unsigned_type>(~base_type(0)) << fractional_bits);
	static constexpr base_type integer_mask    = ~fractional_mask;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

public:
	static constexpr base_type one = base_type(1) << fractional_bits;

public: // constructors
	fixed()            = default;
	fixed(const fixed &)            = default;
	fixed &operator=(const fixed &) = default;

	template <class Number>
	constexpr fixed(Number n, typename std::enable_if<std::is_arithmetic<Number>::value>::type * = nullptr)
		: data_(static_cast<base_type>(n * one)) {
	}

	template <class Number>
	constexpr fixed(Number n, typename std::enable_if<std::is_enum<Number>::value>::type * = nullptr)
		: data_(static_cast<base_type>(n * one)) {
	}

public: // conversion
	template <size_t I2, size_t F2>
	CONSTEXPR14 explicit fixed(fixed<I2, F2> other) {
		static_assert(I2 <= I && F2 <= F, "Scaling conversion can only upgrade types");
		using T = fixed<I2, F2>;

		const base_type fractional = (other.data_ & T::fractional_mask);
		const base_type integer    = (other.data_ & T::integer_mask) >> T::fractional_bits;
		data_                      = (integer << fractional_bits) | (fractional << (fractional_bits - T::fractional_bits));
	}

private:
	// this makes it simpler to create a fixed point object from
	// a native type without scaling
	// use "fixed::from_base" in order to perform this.
	struct NoScale {};

	constexpr fixed(base_type n, const NoScale &)
		: data_(n) {
	}

public:
	constexpr static fixed from_base(base_type n) {
		return fixed(n, NoScale());
	}

public: // comparison operators
	constexpr bool operator==(fixed rhs) const {
		return data_ == rhs.data_;
	}

	constexpr bool operator!=(fixed rhs) const {
		return data_ != rhs.data_;
	}

	constexpr bool operator<(fixed rhs) const {
		return data_ < rhs.data_;
	}

	constexpr bool operator>(fixed rhs) const {
		return data_ > rhs.data_;
	}

	constexpr bool operator<=(fixed rhs) const {
		return data_ <= rhs.data_;
	}

	constexpr bool operator>=(fixed rhs) const {
		return data_ >= rhs.data_;
	}

public: // unary operators
	constexpr bool operator!() const {
		return !data_;
	}

	constexpr fixed operator~() const {
		// NOTE(eteran): this will often appear to "just negate" the value
		// that is not an error, it is because -x == (~x+1)
		// and that "+1" is adding an infinitesimally small fraction to the
		// complimented value
		return fixed::from_base(~data_);
	}

	constexpr fixed operator-() const {
		return fixed::from_base(-data_);
	}

	constexpr fixed operator+() const {
		return fixed::from_base(+data_);
	}

	CONSTEXPR14 fixed &operator++() {
		data_ += one;
		return *this;
	}

	CONSTEXPR14 fixed &operator--() {
		data_ -= one;
		return *this;
	}

	CONSTEXPR14 fixed operator++(int) {
		fixed tmp(*this);
		data_ += one;
		return tmp;
	}

	CONSTEXPR14 fixed operator--(int) {
		fixed tmp(*this);
		data_ -= one;
		return tmp;
	}

public: // basic math operators
	CONSTEXPR14 fixed &operator+=(fixed n) {
		data_ += n.data_;
		return *this;
	}

	CONSTEXPR14 fixed &operator-=(fixed n) {
		data_ -= n.data_;
		return *this;
	}

	CONSTEXPR14 fixed &operator*=(fixed n) {
		return assign(detail::multiply(*this, n));
	}

	CONSTEXPR14 fixed &operator/=(fixed n) {
		fixed temp;
		return assign(detail::divide(*this, n, temp));
	}

private:
	CONSTEXPR14 fixed &assign(fixed rhs) {
		data_ = rhs.data_;
		return *this;
	}

public: // binary math operators, effects underlying bit pattern since these
		// don't really typically make sense for non-integer values
	CONSTEXPR14 fixed &operator&=(fixed n) {
		data_ &= n.data_;
		return *this;
	}

	CONSTEXPR14 fixed &operator|=(fixed n) {
		data_ |= n.data_;
		return *this;
	}

	CONSTEXPR14 fixed &operator^=(fixed n) {
		data_ ^= n.data_;
		return *this;
	}

	template <class Integer, class = typename std::enable_if<std::is_integral<Integer>::value>::type>
	CONSTEXPR14 fixed &operator>>=(Integer n) {
		data_ >>= n;
		return *this;
	}

	template <class Integer, class = typename std::enable_if<std::is_integral<Integer>::value>::type>
	CONSTEXPR14 fixed &operator<<=(Integer n) {
		data_ <<= n;
		return *this;
	}

public: // conversion to basic types
	constexpr uint8_t to_uint8() const {
		return static_cast<uint8_t>((data_ & integer_mask) >> fractional_bits);
	}

	constexpr uint16_t to_uint16() const {
		return static_cast<uint16_t>((data_ & integer_mask) >> fractional_bits);
	}

	constexpr int to_int() const {
		return static_cast<int>((data_ & integer_mask) >> fractional_bits);
	}

	constexpr int64_t to_int64() const {
		return static_cast<int64_t>((data_ & integer_mask) >> fractional_bits);
	}

	constexpr uint64_t to_uint64() const {
		return static_cast<uint64_t>((data_ & integer_mask) >> fractional_bits);
	}

	constexpr unsigned int to_uint() const {
		return static_cast<unsigned int>((data_ & integer_mask) >> fractional_bits);
	}

	constexpr float to_float() const {
		return static_cast<double>(data_) / fixed::one;
	}

	constexpr double to_double() const {
		return static_cast<double>(data_) / fixed::one;
	}

	constexpr base_type to_raw() const {
		return data_;
	}

	operator uint8_t() const {
        return to_uint8();
    }

    operator uint16_t() const {
        return to_uint16();
    }

	operator int64_t() const {
        return to_int64();
    }

    operator uint64_t() const {
        return to_uint64();
    }

    operator bool() const {
        return (bool)!!to_int();
    }

    operator int() const {
        return to_int();
    }

    operator unsigned int() const {
        return to_uint();
    }

    operator float() const {
        return to_float(); 
    }

    operator double() const {
        return to_double(); 
    }

public:
	CONSTEXPR14 void swap(fixed &rhs) {
		using std::swap;
		swap(data_, rhs.data_);
	}

public:
	base_type data_;
};

// if we have the same fractional portion, but differing integer portions, we trivially upgrade the smaller type
template <size_t I1, size_t I2, size_t F>
CONSTEXPR14 typename std::conditional<I1 >= I2, fixed<I1, F>, fixed<I2, F>>::type operator+(fixed<I1, F> lhs, fixed<I2, F> rhs) {

	using T = typename std::conditional<
		I1 >= I2,
		fixed<I1, F>,
		fixed<I2, F>>::type;

	const T l = T::from_base(lhs.to_raw());
	const T r = T::from_base(rhs.to_raw());
	return l + r;
}

template <size_t I1, size_t I2, size_t F>
CONSTEXPR14 typename std::conditional<I1 >= I2, fixed<I1, F>, fixed<I2, F>>::type operator-(fixed<I1, F> lhs, fixed<I2, F> rhs) {

	using T = typename std::conditional<
		I1 >= I2,
		fixed<I1, F>,
		fixed<I2, F>>::type;

	const T l = T::from_base(lhs.to_raw());
	const T r = T::from_base(rhs.to_raw());
	return l - r;
}

template <size_t I1, size_t I2, size_t F>
CONSTEXPR14 typename std::conditional<I1 >= I2, fixed<I1, F>, fixed<I2, F>>::type operator*(fixed<I1, F> lhs, fixed<I2, F> rhs) {

	using T = typename std::conditional<
		I1 >= I2,
		fixed<I1, F>,
		fixed<I2, F>>::type;

	const T l = T::from_base(lhs.to_raw());
	const T r = T::from_base(rhs.to_raw());
	return l * r;
}

template <size_t I1, size_t I2, size_t F>
CONSTEXPR14 typename std::conditional<I1 >= I2, fixed<I1, F>, fixed<I2, F>>::type operator/(fixed<I1, F> lhs, fixed<I2, F> rhs) {

	using T = typename std::conditional<
		I1 >= I2,
		fixed<I1, F>,
		fixed<I2, F>>::type;

	const T l = T::from_base(lhs.to_raw());
	const T r = T::from_base(rhs.to_raw());
	return l / r;
}

template <size_t I, size_t F>
std::ostream &operator<<(std::ostream &os, fixed<I, F> f) {
	os << f.to_double();
	return os;
}

// basic math operators
template <size_t I, size_t F>
CONSTEXPR14 fixed<I, F> operator+(fixed<I, F> lhs, fixed<I, F> rhs) {
	lhs += rhs;
	return lhs;
}

template <size_t I, size_t F>
CONSTEXPR14 fixed<I, F> operator-(fixed<I, F> lhs, fixed<I, F> rhs) {
	lhs -= rhs;
	return lhs;
}

template <size_t I, size_t F>
CONSTEXPR14 fixed<I, F> operator*(fixed<I, F> lhs, fixed<I, F> rhs) {
	lhs *= rhs;
	return lhs;
}

template <size_t I, size_t F>
CONSTEXPR14 fixed<I, F> operator/(fixed<I, F> lhs, fixed<I, F> rhs) {
	lhs /= rhs;
	return lhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
CONSTEXPR14 fixed<I, F> operator+(fixed<I, F> lhs, Number rhs) {
	lhs += fixed<I, F>(rhs);
	return lhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
CONSTEXPR14 fixed<I, F> operator-(fixed<I, F> lhs, Number rhs) {
	lhs -= fixed<I, F>(rhs);
	return lhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
CONSTEXPR14 fixed<I, F> operator*(fixed<I, F> lhs, Number rhs) {
	lhs *= fixed<I, F>(rhs);
	return lhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
CONSTEXPR14 fixed<I, F> operator/(fixed<I, F> lhs, Number rhs) {
	lhs /= fixed<I, F>(rhs);
	return lhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
CONSTEXPR14 fixed<I, F> operator+(Number lhs, fixed<I, F> rhs) {
	fixed<I, F> tmp(lhs);
	tmp += rhs;
	return tmp;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
CONSTEXPR14 fixed<I, F> operator-(Number lhs, fixed<I, F> rhs) {
	fixed<I, F> tmp(lhs);
	tmp -= rhs;
	return tmp;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
CONSTEXPR14 fixed<I, F> operator*(Number lhs, fixed<I, F> rhs) {
	fixed<I, F> tmp(lhs);
	tmp *= rhs;
	return tmp;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
CONSTEXPR14 fixed<I, F> operator/(Number lhs, fixed<I, F> rhs) {
	fixed<I, F> tmp(lhs);
	tmp /= rhs;
	return tmp;
}

// shift operators
template <size_t I, size_t F, class Integer, class = typename std::enable_if<std::is_integral<Integer>::value>::type>
CONSTEXPR14 fixed<I, F> operator<<(fixed<I, F> lhs, Integer rhs) {
	lhs <<= rhs;
	return lhs;
}

template <size_t I, size_t F, class Integer, class = typename std::enable_if<std::is_integral<Integer>::value>::type>
CONSTEXPR14 fixed<I, F> operator>>(fixed<I, F> lhs, Integer rhs) {
	lhs >>= rhs;
	return lhs;
}

// comparison operators
template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator>(fixed<I, F> lhs, Number rhs) {
	return lhs > fixed<I, F>(rhs);
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator<(fixed<I, F> lhs, Number rhs) {
	return lhs < fixed<I, F>(rhs);
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator>=(fixed<I, F> lhs, Number rhs) {
	return lhs >= fixed<I, F>(rhs);
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator<=(fixed<I, F> lhs, Number rhs) {
	return lhs <= fixed<I, F>(rhs);
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator==(fixed<I, F> lhs, Number rhs) {
	return lhs == fixed<I, F>(rhs);
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator!=(fixed<I, F> lhs, Number rhs) {
	return lhs != fixed<I, F>(rhs);
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator>(Number lhs, fixed<I, F> rhs) {
	return fixed<I, F>(lhs) > rhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator<(Number lhs, fixed<I, F> rhs) {
	return fixed<I, F>(lhs) < rhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator>=(Number lhs, fixed<I, F> rhs) {
	return fixed<I, F>(lhs) >= rhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator<=(Number lhs, fixed<I, F> rhs) {
	return fixed<I, F>(lhs) <= rhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator==(Number lhs, fixed<I, F> rhs) {
	return fixed<I, F>(lhs) == rhs;
}

template <size_t I, size_t F, class Number, class = typename std::enable_if<std::is_arithmetic<Number>::value>::type>
constexpr bool operator!=(Number lhs, fixed<I, F> rhs) {
	return fixed<I, F>(lhs) != rhs;
}

}

#undef CONSTEXPR14

#endif
