import React, { useState } from "react";
import {
  IonPage,
  IonHeader,
  IonToolbar,
  IonTitle,
  IonContent,
  IonInput,
  IonButton,
  IonItem,
  IonList,
  IonLabel,
  IonSplitPane,
  IonMenu,
  IonMenuToggle,
  IonRouterOutlet,
  IonIcon,
  IonTextarea,
} from "@ionic/react";

import { menu, close, send, globe, list, logIn, document, code } from "ionicons/icons";

export default function CrawlerUI() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [showLogin, setShowLogin] = useState(false);
  const [error, setError] = useState("");

  const [loginData, setLoginData] = useState({
    username_selector: "#username",
    password_selector: "#password",
    submit_selector: "#submit",
    username: "",
    password: "",
  });

  const API_BASE = "http://localhost:7000/api";

  // -------------------------
  // Crawling Functions
  // -------------------------
  const crawlWebsite = async () => {
    if (!url.trim()) return setError("Please enter a URL");

    setLoading(true);
    setError("");

    try {
      const res = await fetch(`${API_BASE}/crawl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await res.json();
      data.success ? setResults(data) : setError(data.error);
    } catch (e: any) {
      setError("Connection error: " + e.message);
    }

    setLoading(false);
  };

  const crawlWithLogin = async () => {
    if (!url || !loginData.username || !loginData.password)
      return setError("Please fill in login details");

    setLoading(true);
    setError("");

    try {
      const res = await fetch(`${API_BASE}/crawl/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...loginData, url }),
      });

      const data = await res.json();
      data.success ? setResults(data) : setError(data.error);
    } catch (e: any) {
      setError("Connection error: " + e.message);
    }

    setLoading(false);
  };

  const extractForms = async () => {
    if (!url.trim()) return setError("Please enter a URL");

    setLoading(true);
    setError("");

    try {
      const res = await fetch(`${API_BASE}/crawl/forms`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await res.json();
      data.success ? setResults(data) : setError(data.error);
    } catch (e: any) {
      setError("Connection error: " + e.message);
    }

    setLoading(false);
  };

  // -------------------------
  // UI Rendering
  // -------------------------
  return (
    <IonPage>
      <IonSplitPane contentId="main">
        {/* Sidebar Menu */}
        <IonMenu contentId="main">
          <IonHeader>
            <IonToolbar>
              <IonTitle>Web Crawler</IonTitle>
            </IonToolbar>
          </IonHeader>

          <IonContent>
            <IonList>
              <IonItem button onClick={() => setActiveTab("overview")}>
                Overview
              </IonItem>
              <IonItem button onClick={() => setActiveTab("links")}>
                Links
              </IonItem>
              <IonItem button onClick={() => setActiveTab("forms")}>
                Forms
              </IonItem>
              <IonItem button onClick={() => setActiveTab("metadata")}>
                Metadata
              </IonItem>
              <IonItem button onClick={() => setActiveTab("raw")}>
                Raw Data
              </IonItem>
            </IonList>
          </IonContent>
        </IonMenu>

        {/* Main Page */}
        <div className="flex-1" id="main">
          <IonHeader>
            <IonToolbar>
              <IonMenuToggle>
                <IonButton fill="clear">
                  <IonIcon icon={menu} />
                </IonButton>
              </IonMenuToggle>

              <IonTitle>Crawler Dashboard</IonTitle>
            </IonToolbar>
          </IonHeader>

          <IonContent fullscreen className="ion-padding">
            {/* URL Input */}
            <IonItem>
              <IonLabel position="stacked">Website URL</IonLabel>
              <IonInput
                value={url}
                placeholder="https://example.com"
                onIonChange={(e) => setUrl(e.detail.value!)}
              />
            </IonItem>

            {/* Login Section Toggle */}
            <IonButton
              expand="block"
              color="tertiary"
              onClick={() => setShowLogin(!showLogin)}
              className="ion-margin-top"
            >
              {showLogin ? "Hide Login" : "Test Login"}
            </IonButton>

            {/* Login Fields */}
            {showLogin && (
              <>
                <IonItem>
                  <IonLabel position="stacked">Username</IonLabel>
                  <IonInput
                    onIonChange={(e) =>
                      setLoginData({ ...loginData, username: e.detail.value! })
                    }
                  />
                </IonItem>

                <IonItem>
                  <IonLabel position="stacked">Password</IonLabel>
                  <IonInput
                    type="password"
                    onIonChange={(e) =>
                      setLoginData({ ...loginData, password: e.detail.value! })
                    }
                  />
                </IonItem>
              </>
            )}

            {/* Action Buttons */}
            <IonButton
              expand="block"
              color="primary"
              onClick={crawlWebsite}
              disabled={loading}
              className="ion-margin-top"
            >
              Crawl Website
            </IonButton>

            {showLogin && (
              <IonButton
                expand="block"
                color="secondary"
                onClick={crawlWithLogin}
                disabled={loading}
              >
                Crawl with Login
              </IonButton>
            )}

            <IonButton
              expand="block"
              color="success"
              onClick={extractForms}
              disabled={loading}
              className="ion-margin-top"
            >
              Extract Forms
            </IonButton>

            {/* Error Message */}
            {error && (
              <IonItem color="danger" className="ion-margin-top">
                <IonLabel>{error}</IonLabel>
              </IonItem>
            )}

            {/* Results Output */}
            {results && (
              <IonList className="ion-margin-top">
                <IonItem>
                  <IonLabel>
                    <h2>Results</h2>
                    <p>{activeTab.toUpperCase()}</p>
                  </IonLabel>
                </IonItem>

                <IonItem>
                  <IonTextarea
                    autoGrow
                    readonly
                    value={JSON.stringify(results, null, 2)}
                  ></IonTextarea>
                </IonItem>
              </IonList>
            )}
          </IonContent>
        </div>
      </IonSplitPane>
    </IonPage>
  );
}
