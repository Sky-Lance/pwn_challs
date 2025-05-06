open! Base
open! Stdio

type token =
  | Num of Mpz.t
  | Plus
  | Minus
  | Pplus
  | Abs
  | Drop
  | Star
  | Min
  | Amin
  | Max
  | Amax
  | Pi

let string_of_token = function
  | Plus -> "+"
  | Minus -> "-"
  | Pplus -> "++"
  | Pi -> "pi"
  | Amin -> "amin"
  | Min -> "min"
  | Amax -> "amax"
  | Max -> "max"
  | Abs -> "abs"
  | Drop -> "drop"
  | Star -> "*"
  | Num num -> Mpz.to_string num

let initial_state = []
let parse_as_number token = Mpz.of_string_opt token

let parse_token token : token option =
  match String.lowercase token with
  | "abs" -> Some Abs
  | "++" -> Some Pplus
  | "min" -> Some Min
  | "amin" -> Some Amin
  | "max" -> Some Max
  | "amax" -> Some Amax
  | "pi" -> Some Pi
  | "+" -> Some Plus
  | "-" -> Some Minus
  | "*" -> Some Star
  | "drop" -> Some Drop
  | _ -> Option.map ~f:(fun x -> Num x) (parse_as_number token)

let array_op state ~f =
  match state with
  | [] -> Error "Need more elements on stack"
  | count :: state ->
      let actual_count = Mpz.to_int count in
      if actual_count < -1 then
        Error (Printf.sprintf "Must sum a non-negative number of elements")
      else if actual_count > List.length state then
        Error
          (Printf.sprintf
             "Attempting to sum %d elements, but don't have that many on the \
              stack"
             actual_count)
      else
        let to_use, state =
          if actual_count = -1 then (state, [])
          else List.split_n state actual_count
        in
        let to_use = Ctypes.CArray.of_list Mpz.typ to_use in
        Ok (f to_use :: state)

let execute_token state token =
  let[@inline] binop f =
    match state with
    | [] | [ _ ] -> Error "Need more elements on stack"
    | top :: next :: rest ->
        f ~dst:next next top;
        Ok (next :: rest)
  in
  match token with
  | Num value -> Ok (value :: state)
  | Plus -> binop Mpz.add
  | Minus -> (
      match state with
      | [ x ] ->
          Mpz.neg ~dst:x x;
          Ok [ x ]
      | _ -> binop Mpz.sub)
  | Star -> binop Mpz.mul
  | Pplus -> array_op state ~f:Mpz.sum
  | Pi -> array_op state ~f:Mpz.prod
  | Amax -> array_op state ~f:Mpz.array_max
  | Max -> binop Mpz.max
  | Amin -> array_op state ~f:Mpz.array_min
  | Min -> binop Mpz.min
  | Drop -> (
      match state with
      | _ :: rest -> Ok rest
      | [] -> Error "Need at least one element to execute")
  | Abs -> (
      match state with
      | x :: rest ->
          Mpz.abs ~dst:x x;
          Ok (x :: rest)
      | [] -> Error "Need at least one element to execute")

let print_state ?(max_to_show = 5) state =
  let show, rest = List.split_n state max_to_show in
  let nums =
    List.map show ~f:Mpz.to_string |> List.rev |> String.concat ~sep:" "
  in
  let rest = if not (List.is_empty rest) then "..." else "" in
  printf "===== %s %s\n" rest nums

let step state line =
  let tokens, failures =
    String.split line ~on:' '
    |> List.filter ~f:(Fn.non String.is_empty)
    |> List.partition_map ~f:(fun x ->
           match parse_token x with None -> Second x | Some x -> First x)
  in
  if not (List.is_empty failures) then (
    printf "Unable to parse token: %s\n" (List.hd_exn failures);
    state)
  else
    List.fold_until tokens ~init:state
      ~f:(fun state token ->
        match execute_token state token with
        | Ok state -> Continue state
        | Error message ->
            printf "Failed %s: %s\n" (string_of_token token) message;
            Stop [])
      ~finish:Fn.id

let rec loop state =
  print_state state;
  printf "@ ";
  Out_channel.flush stdout;
  match In_channel.input_line stdin with
  | None -> printf "\n"
  | Some line -> step state line |> loop

let main () = loop initial_state
let () = main ()
