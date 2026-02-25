import { useState } from "react";
import axios from "axios";

export default function App() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState([]);
  const [loading, setLoading] = useState(false);

  const startScan = async () => {
    if (!target) return;
    setLoading(true);
    setResult([]);

    try {
      const res = await axios.post("http://localhost:5000/scan", {
        target,
      });

      setResult(res.data.ports);
    } catch (err) {
      console.log(err);
    }

    setLoading(false);
  };

  return (
    <div style={styles.container}>
      <h1>Cyber Port Scanner</h1>

      <input
        placeholder="Enter IP or Domain"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        style={styles.input}
      />

      <button onClick={startScan} style={styles.button}>
        {loading ? "Scanning..." : "Start Scan"}
      </button>

      <div style={{ marginTop: 20 }}>
        {result.map((p, i) => (
          <div key={i} style={styles.row}>
            Port {p.port} → {p.status}
          </div>
        ))}
      </div>
    </div>
  );
}

const styles = {
  container: {
    background: "#0d1117",
    color: "#00ff9f",
    height: "100vh",
    padding: "40px",
    fontFamily: "monospace",
  },
  input: {
    padding: "10px",
    width: "300px",
    background: "black",
    color: "#00ff9f",
    border: "1px solid #00ff9f",
  },
  button: {
    marginLeft: "10px",
    padding: "10px 20px",
    background: "#00ff9f",
    border: "none",
    cursor: "pointer",
  },
  row: {
    marginTop: "8px",
  },
};