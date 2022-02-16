/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import {
  ethers,
  EventFilter,
  Signer,
  BigNumber,
  BigNumberish,
  PopulatedTransaction,
  Contract,
  ContractTransaction,
  Overrides,
  CallOverrides,
} from "ethers";
import { BytesLike } from "@ethersproject/bytes";
import { Listener, Provider } from "@ethersproject/providers";
import { FunctionFragment, EventFragment, Result } from "@ethersproject/abi";
import { TypedEventFilter, TypedEvent, TypedListener } from "./commons";

interface PrimeFactorizationInterface extends ethers.utils.Interface {
  functions: {
    "addProblem(uint256)": FunctionFragment;
    "getProblems()": FunctionFragment;
    "isProblems(uint256)": FunctionFragment;
    "problems(uint256)": FunctionFragment;
    "resolve(uint256[2],uint256[2][2],uint256[2],uint256[1])": FunctionFragment;
    "resolver(uint256)": FunctionFragment;
    "verifyTx(uint256[2],uint256[2][2],uint256[2],uint256[1])": FunctionFragment;
  };

  encodeFunctionData(
    functionFragment: "addProblem",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "getProblems",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "isProblems",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "problems",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "resolve",
    values: [
      [BigNumberish, BigNumberish],
      [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      [BigNumberish, BigNumberish],
      [BigNumberish]
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "resolver",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "verifyTx",
    values: [
      [BigNumberish, BigNumberish],
      [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      [BigNumberish, BigNumberish],
      [BigNumberish]
    ]
  ): string;

  decodeFunctionResult(functionFragment: "addProblem", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "getProblems",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "isProblems", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "problems", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "resolve", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "resolver", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "verifyTx", data: BytesLike): Result;

  events: {};
}

export class PrimeFactorization extends Contract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  listeners<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter?: TypedEventFilter<EventArgsArray, EventArgsObject>
  ): Array<TypedListener<EventArgsArray, EventArgsObject>>;
  off<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  on<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  once<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  removeListener<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  removeAllListeners<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>
  ): this;

  listeners(eventName?: string): Array<Listener>;
  off(eventName: string, listener: Listener): this;
  on(eventName: string, listener: Listener): this;
  once(eventName: string, listener: Listener): this;
  removeListener(eventName: string, listener: Listener): this;
  removeAllListeners(eventName?: string): this;

  queryFilter<EventArgsArray extends Array<any>, EventArgsObject>(
    event: TypedEventFilter<EventArgsArray, EventArgsObject>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEvent<EventArgsArray & EventArgsObject>>>;

  interface: PrimeFactorizationInterface;

  functions: {
    addProblem(
      number: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    "addProblem(uint256)"(
      number: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    getProblems(overrides?: CallOverrides): Promise<[BigNumber[]]>;

    "getProblems()"(overrides?: CallOverrides): Promise<[BigNumber[]]>;

    isProblems(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    "isProblems(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    problems(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    "problems(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    resolve(
      _a: [BigNumberish, BigNumberish],
      _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      _c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    "resolve(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
      _a: [BigNumberish, BigNumberish],
      _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      _c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    resolver(arg0: BigNumberish, overrides?: CallOverrides): Promise<[string]>;

    "resolver(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<[string]>;

    verifyTx(
      a: [BigNumberish, BigNumberish],
      b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<[boolean] & { r: boolean }>;

    "verifyTx(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
      a: [BigNumberish, BigNumberish],
      b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<[boolean] & { r: boolean }>;
  };

  addProblem(
    number: BigNumberish,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  "addProblem(uint256)"(
    number: BigNumberish,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  getProblems(overrides?: CallOverrides): Promise<BigNumber[]>;

  "getProblems()"(overrides?: CallOverrides): Promise<BigNumber[]>;

  isProblems(arg0: BigNumberish, overrides?: CallOverrides): Promise<boolean>;

  "isProblems(uint256)"(
    arg0: BigNumberish,
    overrides?: CallOverrides
  ): Promise<boolean>;

  problems(arg0: BigNumberish, overrides?: CallOverrides): Promise<BigNumber>;

  "problems(uint256)"(
    arg0: BigNumberish,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  resolve(
    _a: [BigNumberish, BigNumberish],
    _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    _c: [BigNumberish, BigNumberish],
    input: [BigNumberish],
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  "resolve(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
    _a: [BigNumberish, BigNumberish],
    _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    _c: [BigNumberish, BigNumberish],
    input: [BigNumberish],
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  resolver(arg0: BigNumberish, overrides?: CallOverrides): Promise<string>;

  "resolver(uint256)"(
    arg0: BigNumberish,
    overrides?: CallOverrides
  ): Promise<string>;

  verifyTx(
    a: [BigNumberish, BigNumberish],
    b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    c: [BigNumberish, BigNumberish],
    input: [BigNumberish],
    overrides?: CallOverrides
  ): Promise<boolean>;

  "verifyTx(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
    a: [BigNumberish, BigNumberish],
    b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    c: [BigNumberish, BigNumberish],
    input: [BigNumberish],
    overrides?: CallOverrides
  ): Promise<boolean>;

  callStatic: {
    addProblem(number: BigNumberish, overrides?: CallOverrides): Promise<void>;

    "addProblem(uint256)"(
      number: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>;

    getProblems(overrides?: CallOverrides): Promise<BigNumber[]>;

    "getProblems()"(overrides?: CallOverrides): Promise<BigNumber[]>;

    isProblems(arg0: BigNumberish, overrides?: CallOverrides): Promise<boolean>;

    "isProblems(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>;

    problems(arg0: BigNumberish, overrides?: CallOverrides): Promise<BigNumber>;

    "problems(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    resolve(
      _a: [BigNumberish, BigNumberish],
      _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      _c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<void>;

    "resolve(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
      _a: [BigNumberish, BigNumberish],
      _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      _c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<void>;

    resolver(arg0: BigNumberish, overrides?: CallOverrides): Promise<string>;

    "resolver(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<string>;

    verifyTx(
      a: [BigNumberish, BigNumberish],
      b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<boolean>;

    "verifyTx(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
      a: [BigNumberish, BigNumberish],
      b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<boolean>;
  };

  filters: {};

  estimateGas: {
    addProblem(
      number: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    "addProblem(uint256)"(
      number: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    getProblems(overrides?: CallOverrides): Promise<BigNumber>;

    "getProblems()"(overrides?: CallOverrides): Promise<BigNumber>;

    isProblems(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    "isProblems(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    problems(arg0: BigNumberish, overrides?: CallOverrides): Promise<BigNumber>;

    "problems(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    resolve(
      _a: [BigNumberish, BigNumberish],
      _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      _c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    "resolve(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
      _a: [BigNumberish, BigNumberish],
      _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      _c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    resolver(arg0: BigNumberish, overrides?: CallOverrides): Promise<BigNumber>;

    "resolver(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    verifyTx(
      a: [BigNumberish, BigNumberish],
      b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    "verifyTx(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
      a: [BigNumberish, BigNumberish],
      b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    addProblem(
      number: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    "addProblem(uint256)"(
      number: BigNumberish,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    getProblems(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    "getProblems()"(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    isProblems(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    "isProblems(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    problems(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    "problems(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    resolve(
      _a: [BigNumberish, BigNumberish],
      _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      _c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    "resolve(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
      _a: [BigNumberish, BigNumberish],
      _b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      _c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    resolver(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    "resolver(uint256)"(
      arg0: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    verifyTx(
      a: [BigNumberish, BigNumberish],
      b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    "verifyTx(uint256[2],uint256[2][2],uint256[2],uint256[1])"(
      a: [BigNumberish, BigNumberish],
      b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
      c: [BigNumberish, BigNumberish],
      input: [BigNumberish],
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;
  };
}