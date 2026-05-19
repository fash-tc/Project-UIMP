import { redirect } from 'next/navigation';

export default function NewStatusIncidentRedirect() {
  redirect('/status/incidents?tab=new');
}
