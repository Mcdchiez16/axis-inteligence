import { redirect } from 'next/navigation';

/** The DNS lookup now lives in the combined Lookup tool. */
export default function Page() {
  redirect('/lookup?type=dns');
}
