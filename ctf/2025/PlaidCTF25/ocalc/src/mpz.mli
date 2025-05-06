type t

val typ : t Ctypes.typ
val create : unit -> t
val of_string_opt : string -> t option
val to_int : t -> int
val to_string : ?base:int -> t -> string
val add : dst:t -> t -> t -> unit
val sub : dst:t -> t -> t -> unit
val mul : dst:t -> t -> t -> unit
val max : dst:t -> t -> t -> unit
val min : dst:t -> t -> t -> unit
val addmul : dst:t -> t -> t -> unit
val neg : dst:t -> t -> unit
val abs : dst:t -> t -> unit
val sum : ?kind:[ `Reduce_binary ] -> t Ctypes.CArray.t -> t
val prod : ?kind:[ `Reduce_binary ] -> t Ctypes.CArray.t -> t
val array_max : ?kind:[ `Reduce_binary ] -> t Ctypes.CArray.t -> t
val array_min : ?kind:[ `Reduce_binary ] -> t Ctypes.CArray.t -> t
