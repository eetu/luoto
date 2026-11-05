// What a folder says about itself (`POST /api/detect`), re-asked 300 ms after the folder or name
// changes. Call it while a component initialises: it registers the effect that does the asking.

import { api } from "$lib/api";
import { errorText } from "$lib/stores/app.svelte";
import type { Proposal } from "$lib/types";

export type DetectQuery = { dir?: string; name?: string };

export type Detection = {
  readonly proposal: Proposal | null;
  readonly error: string | null;
  /** The proposal answers the current query: creating accepts its luoto.toml, so wait for this. */
  readonly ready: boolean;
};

export const useDetect = (
  query: () => DetectQuery,
  onProposal: (p: Proposal) => void,
): Detection => {
  let proposal = $state<Proposal | null>(null);
  let proposedFor = $state<string | null>(null);
  let error = $state<string | null>(null);
  const key = $derived(JSON.stringify(query()));

  $effect(() => {
    const body = query();
    const asked = key;
    if (!body.dir) {
      proposal = null;
      proposedFor = null;
      error = null;
      return;
    }
    let stale = false;
    const timer = setTimeout(() => {
      api
        .detect(body)
        .then((p) => {
          if (stale) return;
          proposal = p;
          proposedFor = asked;
          error = null;
          onProposal(p);
        })
        .catch((e: unknown) => {
          if (stale) return;
          proposal = null;
          proposedFor = null;
          error = errorText(e);
        });
    }, 300);
    return () => {
      stale = true;
      clearTimeout(timer);
    };
  });

  return {
    get proposal() {
      return proposal;
    },
    get error() {
      return error;
    },
    get ready() {
      return proposal !== null && proposedFor === key;
    },
  };
};
