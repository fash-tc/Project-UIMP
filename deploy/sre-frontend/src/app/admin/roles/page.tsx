'use client';
// Slice 1: the original Slice 0 users+roles UI is combined in users/page.tsx.
// The Roles tab links here so navigation works; the combined page handles
// both views internally. A proper split is deferred to a later slice.
export { default } from '../users/page';
