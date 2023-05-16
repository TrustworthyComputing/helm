module s27_bench(blif_clk_net, blif_reset_net, G0, G1, G2, G3, G17);
  wire 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, G10, G11, G13, G5, G6, G7;
  input G0, G1, G2, G3, blif_clk_net, blif_reset_net;
  output G17;
  not g_23_(G6, 16);
  not g_24_(G3, 17);
  not g_25_(G2, 18);
  or g_26_(G0, 16, 19);
  or g_27_(G7, G1, 20);
  or g_28_(17, 20, 21);
  and g_29_(19, 21, 22);
  or g_30_(G5, 22, G17);
  not g_31_(G17, 08);
  and g_32_(18, 20, 09);
  and g_33_(G0, G17, 07);
  dff gG7_reg(09, G7);
  dff gG6_reg(08, G6);
  dff gG5_reg(07, G5);

endmodule
