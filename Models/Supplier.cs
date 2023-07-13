namespace DemoMinimalAPI.Models;

public class Supplier {
    public Guid Id { get; set; }
    public string? Name { get; set; }
    public string? Document { get; set; }
    public bool IsActive { get; set; }
}