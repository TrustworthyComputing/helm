module example(a, b, y);
  input a, b;
  output y;
  wire d1, w1, w2, w3, w4, w5, w6, w7, sel;

  not not_gate1(a, w1);
  nor nor_gate(w1, b, w2);
  xor xor_gate(a, w2, w3);
  not not_gate2(w3, sel);
  xnor xnor_gate(w1, w3, w4);
  nand nand_gate(w2, w4, w5);
  mux mux_gate(w5, a, sel, w7);
  and and_gate(w7, d1, y);
  
  // w5 -> d1
  dff dff1(w5, d1);
endmodule
