
"use client";

import React, { useState } from "react";
import PRInputForm from "./components/PRInputForm";
import AnalysisLoader from "./components/AnalysisLoader";
import ReportView from "./components/ReportView";
import { sampleReviews } from "./lib/data";


export default function Page() {
  const [step, setStep] = useState("input");
  const [provider, setProvider] = useState(null);
  const [reportData, setReportData] = useState(null);

  // Simulate analysis and report generation
  const handleAnalyze = (selectedProvider, prUrl) => {
    setProvider(selectedProvider);
    setStep("loading");
    setTimeout(() => {
      // Use sample data for demo; in real app, fetch from backend
      setReportData(sampleReviews[selectedProvider] || sampleReviews.github);
      setStep("report");
    }, 3500); // Simulate analysis delay
  };

  const handleReset = () => {
    setStep("input");
    setProvider(null);
    setReportData(null);
  };

  return (
    <main>
      {step === "input" && <PRInputForm onAnalyze={handleAnalyze} />}
      {step === "loading" && <AnalysisLoader />}
      {step === "report" && reportData && (
        <ReportView data={reportData} onReset={handleReset} />
      )}
    </main>
  );
}
"use client";

import React, { useState } from "react";
import PRInputForm from "./components/PRInputForm";
import AnalysisLoader from "./components/AnalysisLoader";
import ReportView from "./components/ReportView";
import { sampleReviews } from "./lib/data";


export default function Page() {
  const [step, setStep] = useState("input");
  const [provider, setProvider] = useState(null);
  const [reportData, setReportData] = useState(null);

  // Simulate analysis and report generation
  const handleAnalyze = (selectedProvider, prUrl) => {
    setProvider(selectedProvider);
    setStep("loading");
    setTimeout(() => {
      // Use sample data for demo; in real app, fetch from backend
      setReportData(sampleReviews[selectedProvider] || sampleReviews.github);
      setStep("report");
    }, 3500); // Simulate analysis delay
  };

  const handleReset = () => {
    setStep("input");
    setProvider(null);
    setReportData(null);
  };

  return (
    <main>
      {step === "input" && <PRInputForm onAnalyze={handleAnalyze} />}
      {step === "loading" && <AnalysisLoader />}
      {step === "report" && reportData && (
        <ReportView data={reportData} onReset={handleReset} />
      )}
    </main>
  );
}
