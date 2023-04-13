module adder_2bit(a, b, cin, sum, cout);
  input [1:0] a;
  input [1:0] b;
  input cin;
  output [1:0] sum;
  output cout;

  wire c1, c2, s0, s1;

  // First bit addition
  xor x1(a[0], b[0], s0);
  and a1(a[0], b[0], c1);
  xor x2(s0, cin, sum[0]);
  or o1(c1, cin, c2);

  // Second bit addition
  xor x3(a[1], b[1], s1);
  and a2(a[1], b[1], c1);
  xor x4(s1, c2, sum[1]);
  or o2(c1, c2, cout);

endmodule
