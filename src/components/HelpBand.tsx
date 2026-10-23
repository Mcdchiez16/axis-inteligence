'use client';

import { useState } from 'react';

import { LeadForm } from './LeadForm';
import { Modal } from './Modal';
import { buttonClass, Container } from './ui';

/** The call to action shown above the footer on every page. */
export function HelpBand() {
  const [open, setOpen] = useState(false);
  return (
    <Container className="mt-10 sm:mt-14">
      <div className="warm-dark grid items-center gap-6 overflow-hidden rounded-3xl px-5 py-7 text-white sm:px-10 sm:py-9 md:grid-cols-[minmax(0,1fr)_auto] md:gap-10">
        <div>
          <h2 className="text-xl font-black tracking-tight sm:text-2xl">Need help?</h2>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-white/75 sm:text-base">Axis Solutions can take your domain to full DMARC enforcement, so fake email using your name is rejected and only genuine, authenticated email reaches inboxes.</p>
        </div>
        {/* two equal columns, so both buttons share one width; stacked full width on phones */}
        <div className="grid gap-3 sm:grid-cols-2">
          <button type="button" onClick={() => setOpen(true)} className={`${buttonClass('primary')} h-[52px] whitespace-nowrap`}>Contact us</button>
          <a href="https://axissolafrica.com" target="_blank" rel="noreferrer" className={`${buttonClass('secondary')} h-[52px] whitespace-nowrap`}>Visit Axis Solutions</a>
        </div>
      </div>
      <Modal open={open} onClose={() => setOpen(false)} title="Talk to a specialist">
        <LeadForm endpoint="/api/contact" submitLabel="Send" intro="Tell us a little about your domain and an Axis Solutions specialist will contact you." withMessage />
      </Modal>
    </Container>
  );
}
