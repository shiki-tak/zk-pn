import { ethers } from "ethers";
import { initialize, ZoKratesProvider } from "zokrates-js";

import type { GetStaticProps, NextPage } from "next";
import Head from "next/head";
import { useEffect, useState } from "react";

import type { NextPage } from 'next'
import Image from 'next/image'
import styles from '../styles/Home.module.css'

import PrimeFactorization from './artifacts/contracts/PrimeFactorization.sol/PrimeFactorization.json'
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils/converter";

interface HomeProps {
  proveKeyString: string;
  programString: string;
}

const Home: NextPage = () => {
  const pfAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

  const [inputNumber, setInputNumber] = useState("");
  const [pn1, setPn1] = useState("");
  const [pn2, setPn2] = useState("");

  const [numbers, setNumbers] = useState([]);
  const [zk, setZk] = useState(undefined);

  const fileSystemResolver = async (path) => {
    const source = await fs.readFileSync(path).toString();
    return source;
  };

  useEffect(() => {
    initialize().then((zk) => {
      console.log("zk initialize")
      setZk(zk);
    });
  }, []);

  useEffect(() => {
    fetchProblems();
  }, []);

  async function requestAccount() {
    await window.ethereum.request({ method: 'eth_requestAccounts' });
  }

  async function fetchProblems() {
    if (typeof window.ethereum !== 'undefined') {
      const provider = new ethers.providers.Web3Provider(window.ethereum)
      console.log({ provider })
      const contract = new ethers.Contract(pfAddress, PrimeFactorization.abi, provider)
      try {
        const data = await contract.getProblems()
        setNumbers(data);
        console.log('data: ', data)
      } catch (err) {
        console.log("Error: ", err)
      }
    }
  }

  const handleAddProblem = async (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (typeof window.ethereum !== 'undefined') {
      await requestAccount()
      const provider = new ethers.providers.Web3Provider(window.ethereum);
      console.log({ provider })
      const signer = provider.getSigner()
      const contract = new ethers.Contract(pfAddress, PrimeFactorization.abi, signer)
      const transaction = await contract.addProblem(inputNumber)
      await transaction.wait()
      fetchProblems()
    }
  }
  
  const handleResolve = async (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (!zk) {
      console.log("ZK not exist");
      return;
    }

    if (typeof window.ethereum !== "undefined") {
      await requestAccount()
      const provider = new ethers.providers.Web3Provider(window.ethereum);
      console.log({ provider })
      const signer = provider.getSigner()
      const contract = new ethers.Contract(pfAddress, PrimeFactorization.abi, signer)

      try {
        console.log("ZK compile");
        // compilation
        const artifacts = zk.compile(programString);
        console.log("ZK artifacts");
        const { witness, output } = zk.computeWitness(artifacts, [pn1, pn2]);
        console.log("output: ", output);
        console.log("ZK witness");
        // generate proof
        const proveKey = base64ToArrayBuffer(proveKeyString);
        console.log("ProveKey", proveKey.byteLength);
        const { proof, inputs } = zk.generateProof(
          artifacts.program,
          witness,
          proveKey
        );
        console.log("ZK proof", { proof });
        const transaction = await contract.resolve(
          proof.a,
          proof.b,
          proof.c,
          inputs
        );
        const receipt = await transaction.wait();

      } catch (e) {
        console.log("Error", e);
      }
    }
  }

  return (
    <div className={styles.container}>
      <Head>
        <title>Create Next App</title>
        <meta name="description" content="Generated by create next app" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main className={styles.main}>
        <h1 className={styles.title}>
          Welcome to <a href="https://nextjs.org">Next.js!</a>
        </h1>

        <p className={styles.description}>
          Get started by editing{' '}
          <code className={styles.code}>pages/index.tsx</code>
        </p>

        <div>
          <ul>
            {numbers.map((data) => {
              return (
                <li key={data.toNumber()}>
                  { data.toNumber() }
                  <input
                  value={pn1}
                  onChange={(e) => setPn1(e.target.value)}
                  ></input>
                  <input
                  value={pn2}
                  onChange={(e) => setPn2(e.target.value)}
                  ></input>
                  <button onClick={(e) => handleResolve(e)}>Try</button>
                </li>)
            })}
          </ul>
          <input
              value={inputNumber}
              onChange={(e) => setInputNumber(e.target.value)}
              ></input>
          <button onClick={(e) => handleAddProblem(e)}>Set</button>
        </div>
      </main>

      <footer className={styles.footer}>
        <a
          href="https://vercel.com?utm_source=create-next-app&utm_medium=default-template&utm_campaign=create-next-app"
          target="_blank"
          rel="noopener noreferrer"
        >
          Powered by{' '}
          <span className={styles.logo}>
            <Image src="/vercel.svg" alt="Vercel Logo" width={72} height={16} />
          </span>
        </a>
      </footer>
    </div>
  )
}

export const getStaticProps: GetStaticProps = async (context) => {
  const res = await fetch(
    "https://github.com/shiki-tak/zkp-pn/raw/main/zkp/proving.key"
  );
  const arrayBuffer = await res.arrayBuffer();

  const proveKeyString = arrayBufferToBase64(arrayBuffer);

  const res2 = await fetch(
    "https://github.com/shiki-tak/zkp-pn/raw/main/zkp/pn.zok"
  );

  const programString = await res2.text();

  return {
    props: {
      proveKeyString,
      programString,
    },
  };
};

export default Home
