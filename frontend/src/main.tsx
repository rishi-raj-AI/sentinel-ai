import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import WorkspaceLayer from './workspace3'
import './styles.css'
import './ui2.css'
import './workspace3a.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
    <WorkspaceLayer />
  </React.StrictMode>,
)
