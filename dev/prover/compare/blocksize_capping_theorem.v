(* SPDX-License-Identifier: MIT *)
(* SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>. *)

Require Import Coq.QArith.QArith.
Require Import Coq.QArith.Qround.
Local Open Scope Z_scope.

(*
    (a + b - 1) / b is not directly used here
    (instead, Qceiling (Z.pos a # b) is used).

    This correspondence is proven in multiple places:
    *   https://janmr.com/blog/2009/09/useful-properties-of-the-floor-and-ceil-functions/
    *   https://www3.cs.stonybrook.edu/~cse547/ch3p10,12.pdf
    ... but can be very complex on Coq.
*)
Goal forall a b c:positive,
    Z.pos a <= Z.pos b * Z.pos c <-> Qceiling (Z.pos a # b) <= Z.pos c.
Proof.
    intros a b c.
    split; intro.
    (* Case 1 (forward). *)
    rewrite <- Qceiling_Z.
    apply Qceiling_resp_le.
    apply (Qmult_lt_0_le_reg_r _ _ (inject_Z (Z.pos b))); [reflexivity|].
    rewrite <- inject_Z_mult.
    rewrite Qmult_inject_Z_r.
    rewrite Qreduce_den_r.
    replace (Z.pos a # 1) with (inject_Z (Z.pos a)) by reflexivity.
    rewrite Z.mul_comm.
    rewrite <- Zle_Qle.
    assumption.
    (* Case 2 (backward). *)
    apply (Z.le_trans _ (Z.pos b * Qceiling (Z.pos a # b))).
        (* Case 2A *)
        rewrite Z.mul_comm.
        rewrite Zle_Qle.
        apply (Qmult_lt_0_le_reg_r _ _ (1 # b)); [reflexivity|].
        unfold inject_Z.
        rewrite <- !Qmult_frac_r.
        rewrite Pos.mul_1_l.
        rewrite Qreduce_den_r.
        apply Qle_ceiling.
        (* Case 2B *)
        apply Z.mul_le_mono_pos_l; [reflexivity|].
        assumption.
Qed.
