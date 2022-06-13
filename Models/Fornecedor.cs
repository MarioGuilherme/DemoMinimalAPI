namespace DemoMinimalAPI.Models {
    public class Fornecedor {
        public Guid Id { get; set; }
        public string? Nome { get; set; }
        public string? Documento { get; set; }
        public bool IsAtivo { get; set; }
    }
}