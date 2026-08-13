import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import WorkspaceLayer from './workspace3'
import MissionControl from './mission6'
import IntelligenceWorkspace from './intelligenceWorkspace'
import './styles.css'
import './ui2.css'
import './workspace3a.css'
import './intelligenceWorkspace.css'
import './reportStudio.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
    <WorkspaceLayer />
    <MissionControl />
    <IntelligenceWorkspace />
  </React.StrictMode>,
)
