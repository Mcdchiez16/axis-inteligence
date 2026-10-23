import type { Metadata } from 'next';

import { CidrTool } from '@/components/tools/CidrTool';

export const metadata: Metadata = { title: 'CIDR Calculator' };

export default function Page() {
  return <CidrTool />;
}
