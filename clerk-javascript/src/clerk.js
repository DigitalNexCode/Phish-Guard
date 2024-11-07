import { ClerkProvider, RedirectToSignIn, useUser } from '@clerk/clerk-react';
import { useEffect } from 'react';
import PropTypes from 'prop-types';

const clerkFrontendApi = import.meta.env.VITE_CLERK_FRONTEND_API;

export function ClerkWrapper({ children }) {
    return (
        <ClerkProvider frontendApi={clerkFrontendApi}>
            {children}
        </ClerkProvider>
    );
}

ClerkWrapper.propTypes = {
    children: PropTypes.node.isRequired,
};

export function useClerkUser() {
    const { user, isLoaded } = useUser();

    useEffect(() => {
        if (!isLoaded) return;
        if (!user) {
            // Redirect to sign-in if not logged in
            RedirectToSignIn({ redirectUrl: "https://your-clerk-app-url.com/sign-up" });
        }
    }, [isLoaded, user]);

    return user;
}
