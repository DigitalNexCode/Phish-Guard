import { createRoot } from 'react-dom/client';
import { ClerkWrapper } from './clerk';
import App from './App'; // Assuming you have an App component

const root = createRoot(document.getElementById('root'));
root.render(
    <ClerkWrapper>
        <App />
    </ClerkWrapper>
);
