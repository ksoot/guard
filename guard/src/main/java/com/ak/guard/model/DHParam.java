package com.ak.guard.model;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;

public final class DHParam {

	// The prime that specifies the size of the field
	private BigInteger prime_p = new BigInteger("0");
	// The coefficients a and b of the elliptic curve equation.
	private BigInteger coefficient_a = new BigInteger("0");
	private BigInteger coefficient_b = new BigInteger("0");
	// The base point that specifies the group.
	private ECPoint base_g;
	// The order of the group
	private BigInteger order_n = new BigInteger("0");
	// The cofactor of the subgroup
	private int cofactor_h = 0;
	
	public DHParam(BigInteger prime_p, BigInteger coefficient_a, BigInteger coefficient_b, ECPoint base_g,
			BigInteger order_n, int cofactor_h) {
		super();
		Objects.requireNonNull(prime_p, "null prime_p");
		Objects.requireNonNull(coefficient_a, "null coefficient_a");
		Objects.requireNonNull(coefficient_b, "null coefficient_a");
		Objects.requireNonNull(base_g, "null base_g");
		Objects.requireNonNull(order_n, "null order_n");
		
		this.prime_p = prime_p;
		this.coefficient_a = coefficient_a;
		this.coefficient_b = coefficient_b;
		this.base_g = base_g;
		this.order_n = order_n;
		this.cofactor_h = cofactor_h;
	}

	@JsonProperty("P")
	public BigInteger getPrime_p() {
		return prime_p;
	}

	@JsonProperty("a")
	public BigInteger getCoefficient_a() {
		return coefficient_a;
	}

	@JsonProperty("b")
	public BigInteger getCoefficient_b() {
		return coefficient_b;
	}

	@JsonProperty("G")
	public ECPoint getBase_g() {
		return base_g;
	}

	@JsonProperty("n")
	public BigInteger getOrder_n() {
		return order_n;
	}
	
	@JsonProperty("h")
	public int getCofactor_h() {
		return cofactor_h;
	}
	
	
}
