export const OPS_BASE=(import.meta.env.VITE_OPERATIONS_URL||'http://127.0.0.1:8766').replace(/\/$/,'')
export const ACTIVE_MISSION_KEY='sentinel.activeMissionId'
export const MISSION_EVENT='sentinel:mission-workspace'

export type MissionWorkspace={
  mission_id:string
  snapshot?:{
    mission?:{mission_id?:string;status?:string;objective?:string;case_id?:string|null;approved_by?:string|null}
    supervisor?:{confidence?:number;coverage?:number;blockers?:number;contradictions?:number;verdict?:string;notes?:string[]}
  }
  replay?:{frames?:Array<{frame_id:string;at?:string;label:string;state?:string;stage_id?:string|null}>}
  evidence_workspace?:{
    count?:number
    items?:Array<{evidence_id:string;evidence_type:string;label:string;stage_id?:string|null;confidence?:number|null;counter_evidence?:boolean;attack_techniques?:string[];source?:string|null}>
    facets?:{types?:Record<string,number>;counter_evidence?:number}
  }
  twin?:{nodes?:Array<{node_id:string;label:string;state:string;evidence_count?:number}>;edges?:Array<{source:string;target:string;kind:string}>}
  review?:{
    quality_score?:number
    recommended_action?:string
    disagreements?:Array<{stage_id?:string;reason?:string}>
    stage_reviews?:Array<{stage_id:string;agent:string;state:string;supporting_evidence:number;counter_evidence:number;assessment:string}>
  }
  memory?:{related?:Array<{mission_id:string;objective:string;status:string;similarity:number;reasons:string[];case_id?:string|null}>;lessons?:Array<{lesson:string;created_at:string}>}
}

export async function loadMissionWorkspace(missionId:string):Promise<MissionWorkspace>{
  const id=missionId.trim().toUpperCase()
  if(!id) throw new Error('mission id required')
  const r=await fetch(`${OPS_BASE}/api/x/operations/missions/${encodeURIComponent(id)}/workspace`,{headers:{Accept:'application/json'}})
  if(!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<MissionWorkspace>
}

export function rememberActiveMission(workspace:MissionWorkspace){
  try{localStorage.setItem(ACTIVE_MISSION_KEY,workspace.mission_id)}catch{}
  window.dispatchEvent(new CustomEvent<MissionWorkspace>(MISSION_EVENT,{detail:workspace}))
}

export function activeMissionId(){
  try{return localStorage.getItem(ACTIVE_MISSION_KEY)||''}catch{return ''}
}
