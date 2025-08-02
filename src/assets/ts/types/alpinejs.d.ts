declare module 'alpinejs' {
  export interface Alpine {
    data: (name: string, data: () => any) => void;
    start: () => void;
    [key: string]: any;
  }
  const Alpine: Alpine;
  export default Alpine;
}