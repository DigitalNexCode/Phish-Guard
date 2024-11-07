// clerk.js
import { ClerkProvider, RedirectToSignIn, useUser } from '@clerk/clerk-react';
import { useEffect } from 'react';

const clerkFrontendApi = process.env.CLERK_FRONTEND_API;

export function ClerkWrapper({ children }) {
    return (
        <ClerkProvider frontendApi={clerkFrontendApi}>
            {children}
        </ClerkProvider>
    );
}

export function useClerkUser() {
    const { user, isLoaded } = useUser();

    useEffect(() => {
        if (!isLoaded) return;
        if (!user) {
            // Redirect to sign-in if not logged in
            RedirectToSignIn();
        }
    }, [isLoaded, user]);

    return user;
}
