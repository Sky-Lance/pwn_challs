open Gmp_generated.Type
open Gmp_generated.Functions
module Array = Ctypes.CArray

type t = (mpz Ctypes.structure, [ `C ]) Ctypes.pointer

let typ = Gmp_generated.Type.mpz

let create () =
  let result = Ctypes.allocate_n ~finalise:mpz_clear mpz_struct ~count:1 in
  mpz_init result;
  result

let parse_with = create ()

let of_string_opt str =
  if mpz_set_str parse_with str 0 = 0 then (
    let result = create () in
    mpz_swap parse_with result;
    Some result)
  else None

let to_int x =
  let result = mpz_get_si x in
  Signed.Long.to_int result

let nullchar = Ctypes.(coerce (ptr void) (ptr char) null)

let to_string ?(base = 10) x =
  let char_ptr = mpz_get_str nullchar base x in
  let result = Ctypes_std_views.string_of_char_ptr char_ptr in
  free_char_ptr char_ptr;
  result

let add ~dst a b = mpz_add dst a b
let mul ~dst a b = mpz_mul dst a b
let max ~dst a b = mpz_set dst (if mpz_cmp a b < 0 then b else a)
let min ~dst a b = mpz_set dst (if mpz_cmp a b > 0 then b else a)
let sub ~dst a b = mpz_sub dst a b
let addmul ~dst a b = mpz_addmul dst a b
let neg ~dst a = mpz_neg dst a
let abs ~dst a = mpz_abs dst a

let reduce_binary array ~f =
  let rec inner arr ~lo ~hi =
    assert (lo < hi);
    match hi - lo with
    | 1 -> Array.get arr lo
    | diff ->
        let mid = lo + (diff / 2) in
        let a = inner arr ~lo ~hi:mid in
        let b = inner arr ~lo:mid ~hi in
        f ~dst:a a b;
        a
  in
  let length = Array.length array in
  if length = 0 then None else Some (inner array ~lo:0 ~hi:length)

let sum_reduce_binary array =
  match reduce_binary array ~f:add with
  | None -> create ()
  | Some result -> result

let prod_reduce_binary array =
  match reduce_binary array ~f:mul with
  | None ->
      let result = create () in
      mpz_set_si result 1;
      result
  | Some result -> result

let array_max_reduce_binary array =
  match reduce_binary array ~f:max with
  | None -> create ()
  | Some result -> result

let array_min_reduce_binary array =
  match reduce_binary array ~f:max with
  | None -> create ()
  | Some result -> result

(* TODO: add simd implementations *)
let sum ?(kind = `Reduce_binary) (array : t Ctypes.CArray.t) =
  match kind with `Reduce_binary -> sum_reduce_binary array

let prod ?(kind = `Reduce_binary) (array : t Ctypes.CArray.t) =
  match kind with `Reduce_binary -> prod_reduce_binary array

let array_max ?(kind = `Reduce_binary) (array : t Ctypes.CArray.t) =
  match kind with `Reduce_binary -> array_max_reduce_binary array

let array_min ?(kind = `Reduce_binary) (array : t Ctypes.CArray.t) =
  match kind with `Reduce_binary -> array_min_reduce_binary array
