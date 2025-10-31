import React from 'react';
// --- ✅ 1. CAMBIO: Importar HashRouter en lugar de BrowserRouter ---
import { HashRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
// --- ✅ 2. IMPORTAR EL PROVEEDOR DE PAYPAL ---
import { PayPalScriptProvider } from '@paypal/react-paypal-js';

// Importar tus componentes
import Login from './components/login';
import './styles/style.css';
import CrearUsuario from './components/CrearUsuario';
import RegistroAlumno from './components/RegistroAlumno';
import RegistroMaestro from './components/RegistroMaestro';
import DashboardMaestro from './components/DashboardMaestro';
import DashboardAlumno from './components/DashboardAlumno';
import NuevaAsesoria from './components/NuevaAsesoria';
import SolicitarAsesoria from './components/SolicitarAsesoria';
import VerAsesoria from './components/VerAsesoria';
import VerAsesoriaTotales from './components/VerAsesoriaTotales';
import EditarAsesoria from './components/EditarAsesoria';
import PagoAsesoria from './components/PagoAsesoria';
import VerDetalleAsesoria from './components/VerDetalleAsesoria';
import ProtectedRoute from './components/ProtectedRoute'; // Importar el componente de protección

// --- ✅ 3. CONFIGURAR LAS OPCIONES DE PAYPAL CON TU CLIENT ID ---
const initialOptions = {
  "client-id": "AdvfsRKnu0BtjZInLx1F1z7JwemhDBYfjlxgltBjbcwGqczjp2Ihg-Rv-2EZmm-U63WEigRX0eqAjQXL", 
  currency: "MXN", // Moneda (Pesos Mexicanos)
  intent: "capture", // Intención de capturar el pago inmediatamente
};


function App() {
  return (
    // --- ✅ 4. ENVOLVER TU APP CON EL PROVEEDOR ---
    <PayPalScriptProvider options={initialOptions}>
      <Router>
        <Routes>
          {/* --- Rutas Públicas --- */}
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/login" element={<Login />} />
          <Route path="/crear_usuario" element={<CrearUsuario />} />
          <Route path="/registro_alumno" element={<RegistroAlumno />} />
          <Route path="/registro_maestro" element={<RegistroMaestro />} />

          
          {/* --- Rutas Protegidas para Alumnos --- */}
          <Route 
            path="/dashboard_alumno" 
            element={
              <ProtectedRoute roleRequired="alumno">
                <DashboardAlumno />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/ver_asesoria/:id" 
            element={
              <ProtectedRoute roleRequired="alumno">
                <VerAsesoria />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/pago_asesoria/:id" 
            element={
              <ProtectedRoute roleRequired="alumno">
                <PagoAsesoria />
              </ProtectedRoute>
            } 
          />
           <Route 
            path="/ver_asesorias_totales" 
            element={
              <ProtectedRoute roleRequired="alumno">
                <VerAsesoriaTotales />
              </ProtectedRoute>
            } 
          />
           <Route 
            path="/solicitar_asesoria" 
            element={
              <ProtectedRoute roleRequired="alumno">
                <SolicitarAsesoria />
              </ProtectedRoute>
            } 
          />
          
          {/* --- Rutas Protegidas para Maestros --- */}
          <Route 
            path="/dashboard_maestro" 
            element={
              <ProtectedRoute roleRequired="maestro">
                <DashboardMaestro />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/nueva_asesoria" 
            element={
              <ProtectedRoute roleRequired="maestro">
                <NuevaAsesoria />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/editar_asesoria/:id" 
            element={
              <ProtectedRoute roleRequired="maestro">
                <EditarAsesoria />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/ver_detalle_asesoria_maestro/:id" 
            element={
              <ProtectedRoute roleRequired="maestro">
                <VerDetalleAsesoria />
              </ProtectedRoute>
            } 
          />
          
          <Route 
            path="/ver_detalle_asesoria/:id" 
            element={
              <ProtectedRoute roleRequired="alumno">
                <VerAsesoria />
              </ProtectedRoute>
            } 
          />

          <Route path="*" element={<Navigate to="/login" replace />} />

        </Routes>
      </Router>
    </PayPalScriptProvider>
  );
}

export default App;
