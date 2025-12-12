// 🛡️ Utilitaires de monitoring pour la sécurité CVE-2025-55183/55184

export function withMonitoring<T extends unknown[], R>(
  fn: (...args: T) => Promise<R>,
  functionName: string
) {
  return async (...args: T): Promise<R> => {
    const startTime = Date.now();
    
    try {
      const result = await fn(...args);
      
      // Log des métriques
      console.log(`[${functionName}] Success in ${Date.now() - startTime}ms`);
      
      return result;
    } catch (error) {
      // Log des erreurs
      console.error(`[${functionName}] Error:`, error);
      throw error;
    }
  };
}

// 🔒 Utilitaire de validation de taille de payload
export function validatePayloadSize(formData: FormData, maxSizeKB: number = 1): boolean {
  const dataSize = new Blob([formData.toString()]).size;
  return dataSize <= maxSizeKB * 1024;
}