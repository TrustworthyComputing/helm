module adder_2bit(a, b, cin, sum, cout);
  input [1:0] a;
  input [1:0] b;
  input cin;
  output [1:0] sum;
  output cout;

  wire c0;
  wire c1;
  wire c2;
  wire i0;
  wire i1;
  wire s0;
  wire s1;

  // First bit addition
  xor x1(a[0], b[0], s0);
  and a1(a[0], b[0], c0);
  xor x2(s0, cin, sum[0]);
  and a2(s0, cin, i0);
  or o1(i0, c0, c1);

  // Last bit addition
  xor x3(a[1], b[1], s1);
  and a3(a[1], b[1], c2);
  xor x4(s1, c1, sum[1]);
  or o2(i1, c2, cout);
  and a4(s1, c1, i1);
endmodule
